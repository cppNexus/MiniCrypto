#include "core/crypto.h"
#include "core/dir_ops.h"
#include "core/format.h"
#include "core/keygen.h"
#include "core/secure_memory.h"
#include "core/file_ops.h"

#include <sodium.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cassert>
#include <cstring>
#include <filesystem>

using namespace minicrypto;

static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "  FAILED: " << msg << " (" << __FILE__ << ":" << __LINE__ << ")\n"; \
            g_tests_failed++; \
            return; \
        } \
    } while (0)

#define RUN_TEST(fn) \
    do { \
        std::cout << "[TEST] Running " << #fn << "..." << std::flush; \
        int before_fail = g_tests_failed; \
        fn(); \
        if (g_tests_failed == before_fail) { \
            std::cout << " \033[32mPASSED\033[0m\n"; \
            g_tests_passed++; \
        } \
    } while (0)

// ── Test helpers ─────────────────────────────────────────────────────────────

static void write_file(const std::string& path, const std::string& content) {
    std::ofstream f(path, std::ios::binary);
    f.write(content.data(), static_cast<std::streamsize>(content.size()));
}

static std::string read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
}

static void remove_file(const std::string& path) {
    std::error_code ec;
    std::filesystem::remove(path, ec);
}

static void remove_rf(const std::string& path) {
    remove_directory_recursive(path);
    remove_file(path);
}

// ── Test Cases ────────────────────────────────────────────────────────────────

void test_secure_memory() {
    // SecureBuffer
    {
        SecureBuffer buf(64);
        TEST_ASSERT(buf.data() != nullptr, "buffer data must not be null");
        TEST_ASSERT(buf.size() == 64, "buffer size must be 64");
        std::memset(buf.data(), 0xAA, 64);
        TEST_ASSERT(buf.data()[0] == 0xAA, "buffer contents must be set");
    }

    // SecureString
    {
        const char* raw = "secret_passphrase_123";
        SecureString s(raw, std::strlen(raw));
        TEST_ASSERT(s.size() == std::strlen(raw), "secure string size match");
        TEST_ASSERT(std::string(s.c_str()) == raw, "secure string content match");
        TEST_ASSERT(!s.empty(), "secure string not empty");

        // Move semantics
        SecureString s2 = std::move(s);
        TEST_ASSERT(s2.size() == std::strlen(raw), "moved secure string size");
        TEST_ASSERT(std::string(s2.c_str()) == raw, "moved secure string content");
    }
}

void test_header_validation() {
    Header h{};
    h.magic = MAGIC;
    h.version = VERSION_CURRENT;
    h.argon_time = 3;
    h.argon_mem_kb = 128 * 1024;
    h.argon_threads = 2;
    h.mode = static_cast<uint8_t>(EncryptionMode::STANDARD);

    TEST_ASSERT(validate_header(h) == HeaderStatus::VALID, "valid header check");

    // Invalid magic
    h.magic = 0x12345678;
    TEST_ASSERT(validate_header(h) == HeaderStatus::INVALID_MAGIC, "invalid magic check");
    h.magic = MAGIC;

    // Unsupported version
    h.version = 1;
    TEST_ASSERT(validate_header(h) == HeaderStatus::UNSUPPORTED_VERSION, "v1 version check");
    h.version = 99;
    TEST_ASSERT(validate_header(h) == HeaderStatus::UNSUPPORTED_VERSION, "future version check");
    h.version = VERSION_CURRENT;

    // Bad argon params
    h.argon_time = 0;
    TEST_ASSERT(validate_header(h) == HeaderStatus::CORRUPTED, "zero argon time");
    h.argon_time = 3;

    h.argon_mem_kb = 2; // too small
    TEST_ASSERT(validate_header(h) == HeaderStatus::CORRUPTED, "too small argon memory");
    h.argon_mem_kb = 128 * 1024;

    h.argon_threads = 0;
    TEST_ASSERT(validate_header(h) == HeaderStatus::CORRUPTED, "zero threads");
    h.argon_threads = 2;

    h.mode = 99;
    TEST_ASSERT(validate_header(h) == HeaderStatus::CORRUPTED, "unknown mode");
}

void test_standard_encryption_roundtrip() {
    const std::string plain_path = "test_std_plain.tmp";
    const std::string enc_path   = "test_std_enc.tmp";
    const std::string dec_path   = "test_std_dec.tmp";
    const std::string content    = "Hello, MiniCrypto Standard Encryption Test!";

    write_file(plain_path, content);

    SecureString pass("pass12345", 9);
    EncryptParams ep;
    ep.mode = EncryptionMode::STANDARD;
    ep.argon_time = 1;      // Low cost for speedy unit tests
    ep.argon_mem_kb = 8192; // 8 MB
    ep.argon_threads = 1;

    encrypt_file(plain_path, enc_path, pass, ep);

    DecryptParams dp;
    dp.mode = EncryptionMode::STANDARD;
    decrypt_file(enc_path, dec_path, pass, dp);

    TEST_ASSERT(read_file(dec_path) == content, "decrypted content must match original");

    // Verification helper
    bool verified = verify_encryption(plain_path, enc_path, pass, dp);
    TEST_ASSERT(verified, "verify_encryption helper must return true");

    remove_file(plain_path);
    remove_file(enc_path);
    remove_file(dec_path);
}

void test_split_key_mode() {
    const std::string plain_path   = "test_split_plain.tmp";
    const std::string enc_path     = "test_split_enc.tmp";
    const std::string dec_path     = "test_split_dec.tmp";
    const std::string content      = "Testing 2-Factor Split Key Encryption Mode";
    std::vector<uint8_t> keyfile   = {0x01, 0x02, 0x03, 0x04, 0x05, 0xAA, 0xBB, 0xCC};

    write_file(plain_path, content);

    SecureString pass("user_pass", 9);
    EncryptParams ep;
    ep.mode = EncryptionMode::SPLIT_KEY;
    ep.keyfile = &keyfile;
    ep.argon_time = 1;
    ep.argon_mem_kb = 8192;
    ep.argon_threads = 1;

    encrypt_file(plain_path, enc_path, pass, ep);

    DecryptParams dp;
    dp.mode = EncryptionMode::SPLIT_KEY;
    dp.keyfile = &keyfile;

    decrypt_file(enc_path, dec_path, pass, dp);
    TEST_ASSERT(read_file(dec_path) == content, "split-key decrypted content matches");

    // Decrypt with wrong keyfile must fail
    std::vector<uint8_t> bad_keyfile = {0x00, 0x00, 0x00};
    dp.keyfile = &bad_keyfile;
    bool caught = false;
    try {
        decrypt_file(enc_path, dec_path, pass, dp);
    } catch (const CryptoException& e) {
        if (e.get_code() == ErrorCode::AUTH_FAILED) caught = true;
    }
    TEST_ASSERT(caught, "wrong keyfile in split-key must trigger AUTH_FAILED");

    remove_file(plain_path);
    remove_file(enc_path);
    remove_file(dec_path);
}

void test_key_only_mode() {
    const std::string plain_path = "test_keyonly_plain.tmp";
    const std::string enc_path   = "test_keyonly_enc.tmp";
    const std::string dec_path   = "test_keyonly_dec.tmp";
    const std::string content    = "Pure Keyfile Machine-to-Machine Secret";
    std::vector<uint8_t> keyfile = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};

    write_file(plain_path, content);

    SecureString empty_pass;
    EncryptParams ep;
    ep.mode = EncryptionMode::KEY_ONLY;
    ep.keyfile = &keyfile;

    encrypt_file(plain_path, enc_path, empty_pass, ep);

    DecryptParams dp;
    dp.mode = EncryptionMode::KEY_ONLY;
    dp.keyfile = &keyfile;

    decrypt_file(enc_path, dec_path, empty_pass, dp);
    TEST_ASSERT(read_file(dec_path) == content, "key-only decrypted content matches");

    remove_file(plain_path);
    remove_file(enc_path);
    remove_file(dec_path);
}

void test_headerless_mode() {
    const std::string plain_path = "test_hdrless_plain.tmp";
    const std::string enc_path   = "test_hdrless_enc.tmp";
    const std::string dec_path   = "test_hdrless_dec.tmp";
    const std::string content    = "Hidden in plain sight - Headerless payload";

    write_file(plain_path, content);

    SecureString pass("stego_pass", 10);
    EncryptParams ep;
    ep.mode = EncryptionMode::HEADERLESS;
    ep.argon_time = 1;
    ep.argon_mem_kb = 8192;
    ep.argon_threads = 1;

    encrypt_file(plain_path, enc_path, pass, ep);

    DecryptParams dp;
    dp.mode = EncryptionMode::HEADERLESS;
    dp.argon_time = 1;
    dp.argon_mem_kb = 8192;
    dp.argon_threads = 1;

    decrypt_file(enc_path, dec_path, pass, dp);
    TEST_ASSERT(read_file(dec_path) == content, "headerless decrypted content matches");

    remove_file(plain_path);
    remove_file(enc_path);
    remove_file(dec_path);
}

void test_deterministic_mode() {
    const std::string plain_path = "test_det_plain.tmp";
    const std::string enc1_path  = "test_det_enc1.tmp";
    const std::string enc2_path  = "test_det_enc2.tmp";
    const std::string dec_path   = "test_det_dec.tmp";
    const std::string content    = "Identical plaintexts will yield identical ciphertexts";

    write_file(plain_path, content);

    SecureString pass("dedup_pass", 10);
    EncryptParams ep;
    ep.mode = EncryptionMode::STANDARD;
    ep.argon_time = 1;
    ep.argon_mem_kb = 8192;
    ep.argon_threads = 1;
    ep.deterministic_salt = true;
    ep.deterministic_confirm_callback = []() { return true; };

    encrypt_file(plain_path, enc1_path, pass, ep);
    encrypt_file(plain_path, enc2_path, pass, ep);

    // Both ciphertexts must be identical byte-for-byte
    std::string c1 = read_file(enc1_path);
    std::string c2 = read_file(enc2_path);
    TEST_ASSERT(c1 == c2, "deterministic mode must produce identical ciphertexts");

    // Decrypt must work
    DecryptParams dp;
    dp.mode = EncryptionMode::STANDARD;
    decrypt_file(enc1_path, dec_path, pass, dp);
    TEST_ASSERT(read_file(dec_path) == content, "deterministic decryption matches");

    remove_file(plain_path);
    remove_file(enc1_path);
    remove_file(enc2_path);
    remove_file(dec_path);
}

void test_tamper_detection() {
    const std::string plain_path = "test_tamper_plain.tmp";
    const std::string enc_path   = "test_tamper_enc.tmp";
    const std::string dec_path   = "test_tamper_dec.tmp";
    const std::string content    = "Data that must not be altered without detection!";

    write_file(plain_path, content);

    SecureString pass("tamper_pass", 11);
    EncryptParams ep;
    ep.argon_time = 1;
    ep.argon_mem_kb = 8192;
    ep.argon_threads = 1;

    encrypt_file(plain_path, enc_path, pass, ep);

    // Tamper with the ciphertext: flip 1 byte towards the end
    {
        std::fstream f(enc_path, std::ios::in | std::ios::out | std::ios::binary);
        f.seekp(-5, std::ios::end);
        char b = 0;
        f.read(&b, 1);
        b ^= 0x55;
        f.seekp(-5, std::ios::end);
        f.write(&b, 1);
    }

    DecryptParams dp;
    bool caught = false;
    try {
        decrypt_file(enc_path, dec_path, pass, dp);
    } catch (const CryptoException& e) {
        if (e.get_code() == ErrorCode::AUTH_FAILED) caught = true;
    }
    TEST_ASSERT(caught, "tampered ciphertext must be detected by AEAD poly1305 MAC");

    remove_file(plain_path);
    remove_file(enc_path);
    remove_file(dec_path);
}

void test_wrong_password() {
    const std::string plain_path = "test_wrongp_plain.tmp";
    const std::string enc_path   = "test_wrongp_enc.tmp";
    const std::string dec_path   = "test_wrongp_dec.tmp";

    write_file(plain_path, "Secret Data");

    SecureString correct_pass("correct_password", 16);
    EncryptParams ep;
    ep.argon_time = 1;
    ep.argon_mem_kb = 8192;
    ep.argon_threads = 1;

    encrypt_file(plain_path, enc_path, correct_pass, ep);

    SecureString wrong_pass("totally_wrong_pw", 16);
    DecryptParams dp;
    bool caught = false;
    try {
        decrypt_file(enc_path, dec_path, wrong_pass, dp);
    } catch (const CryptoException& e) {
        if (e.get_code() == ErrorCode::AUTH_FAILED) caught = true;
    }
    TEST_ASSERT(caught, "wrong password must throw AUTH_FAILED");

    remove_file(plain_path);
    remove_file(enc_path);
    remove_file(dec_path);
}

void test_large_file_streaming() {
    const std::string plain_path = "test_large_plain.tmp";
    const std::string enc_path   = "test_large_enc.tmp";
    const std::string dec_path   = "test_large_dec.tmp";

    // 2.5 MB (exceeds 1 MB CHUNK_SIZE so multiple stream chunks are exercised)
    const size_t total_size = static_cast<size_t>(2.5 * 1024 * 1024);
    {
        std::ofstream f(plain_path, std::ios::binary);
        std::vector<char> chunk(65536, 'X');
        size_t written = 0;
        while (written < total_size) {
            size_t to_write = std::min(chunk.size(), total_size - written);
            f.write(chunk.data(), static_cast<std::streamsize>(to_write));
            written += to_write;
        }
    }

    SecureString pass("streaming_pass", 14);
    EncryptParams ep;
    ep.argon_time = 1;
    ep.argon_mem_kb = 8192;
    ep.argon_threads = 1;

    uint64_t last_progress = 0;
    ep.progress_callback = [&](uint64_t b) { last_progress = b; };

    encrypt_file(plain_path, enc_path, pass, ep);
    TEST_ASSERT(last_progress == total_size, "progress callback reported total size");

    DecryptParams dp;
    decrypt_file(enc_path, dec_path, pass, dp);

    TEST_ASSERT(read_file(dec_path).size() == total_size, "large file decrypted size matches");

    remove_file(plain_path);
    remove_file(enc_path);
    remove_file(dec_path);
}

void test_empty_file() {
    const std::string plain_path = "test_empty_plain.tmp";
    const std::string enc_path   = "test_empty_enc.tmp";
    const std::string dec_path   = "test_empty_dec.tmp";

    write_file(plain_path, "");

    SecureString pass("pass", 4);
    EncryptParams ep;
    ep.argon_time = 1;
    ep.argon_mem_kb = 8192;
    ep.argon_threads = 1;

    encrypt_file(plain_path, enc_path, pass, ep);

    DecryptParams dp;
    decrypt_file(enc_path, dec_path, pass, dp);

    TEST_ASSERT(read_file(dec_path).empty(), "empty file roundtrip succeeds");

    remove_file(plain_path);
    remove_file(enc_path);
    remove_file(dec_path);
}

void test_directory_pack_unpack() {
    const std::string test_dir    = "test_pack_dir";
    const std::string archive     = "test_archive.mcda";
    const std::string unpack_dir  = "test_unpack_dir";

    std::filesystem::create_directories(test_dir + "/sub1");
    std::filesystem::create_directories(test_dir + "/sub2/nested");
    std::filesystem::create_directories(test_dir + "/empty/nested");

    write_file(test_dir + "/root.txt", "Root content");
    write_file(test_dir + "/sub1/file1.txt", "File 1 in sub1");
    write_file(test_dir + "/sub2/file2.txt", "File 2 in sub2");
    write_file(test_dir + "/sub2/nested/deep.txt", "Deep nested file content");
    write_file(test_dir + "/empty_file.txt", "");

    pack_directory(test_dir, archive);

    unpack_directory(archive, unpack_dir);

    TEST_ASSERT(read_file(unpack_dir + "/root.txt") == "Root content", "root.txt unpack match");
    TEST_ASSERT(read_file(unpack_dir + "/sub1/file1.txt") == "File 1 in sub1", "sub1/file1.txt match");
    TEST_ASSERT(read_file(unpack_dir + "/sub2/file2.txt") == "File 2 in sub2", "sub2/file2.txt match");
    TEST_ASSERT(read_file(unpack_dir + "/sub2/nested/deep.txt") == "Deep nested file content", "deep.txt match");
    TEST_ASSERT(std::filesystem::is_directory(unpack_dir + "/empty"), "empty directory is restored");
    TEST_ASSERT(std::filesystem::is_directory(unpack_dir + "/empty/nested"), "nested empty directory is restored");
    TEST_ASSERT(std::filesystem::is_regular_file(unpack_dir + "/empty_file.txt"), "zero-byte file remains a file");
    TEST_ASSERT(read_file(unpack_dir + "/empty_file.txt").empty(), "zero-byte file remains empty");

    remove_rf(test_dir);
    remove_rf(unpack_dir);
    remove_file(archive);
}

void test_directory_encryption_roundtrip() {
    const std::string test_dir   = "test_enc_dir";
    const std::string enc_path   = "test_dir.mcc";
    const std::string dec_dir    = "test_dec_dir";

    std::filesystem::create_directories(test_dir + "/docs");
    write_file(test_dir + "/readme.md", "# Encrypted Directory Project");
    write_file(test_dir + "/docs/notes.txt", "Confidential notes inside directory");

    SecureString pass("dir_password_99", 15);
    EncryptParams ep;
    ep.argon_time = 1;
    ep.argon_mem_kb = 8192;
    ep.argon_threads = 1;

    encrypt_directory(test_dir, enc_path, pass, ep);
    TEST_ASSERT(is_regular_file(enc_path), "encrypted archive file must exist");

    DecryptParams dp;
    decrypt_directory(enc_path, dec_dir, pass, dp);

    TEST_ASSERT(is_directory(dec_dir), "decrypted directory must exist");
    TEST_ASSERT(read_file(dec_dir + "/readme.md") == "# Encrypted Directory Project", "readme content match");
    TEST_ASSERT(read_file(dec_dir + "/docs/notes.txt") == "Confidential notes inside directory", "docs/notes match");

    remove_rf(test_dir);
    remove_rf(dec_dir);
    remove_file(enc_path);
}

void test_atomic_file() {
    const std::string target = "test_atomic.txt";
    remove_file(target);

    // Aborted atomic write
    {
        AtomicFile af(target);
        af.get() << "will not commit";
    }
    TEST_ASSERT(!is_regular_file(target), "aborted AtomicFile must not create target");
    TEST_ASSERT(!is_regular_file(target + ".tmp"), "aborted AtomicFile must clean up temp");

    // Committed atomic write
    {
        AtomicFile af(target);
        af.get() << "committed content";
        af.commit();
    }
    TEST_ASSERT(is_regular_file(target), "committed AtomicFile must create target");
    TEST_ASSERT(read_file(target) == "committed content", "committed content match");

    remove_file(target);
}

void test_path_traversal_prevention() {
    const std::string bad_archive = "test_traversal.mcda";
    const std::string unpack_dir  = "test_traversal_dir";

    // Fabricate an archive with path "../escaped.txt"
    {
        std::ofstream out(bad_archive, std::ios::binary);
        uint32_t magic = ARCHIVE_MAGIC;
        uint32_t ver   = ARCHIVE_VERSION;
        out.write(reinterpret_cast<char*>(&magic), 4);
        out.write(reinterpret_cast<char*>(&ver), 4);

        std::string evil_path = "../escaped.txt";
        uint16_t path_len = static_cast<uint16_t>(evil_path.size());
        out.write(reinterpret_cast<char*>(&path_len), 2);
        out.write(evil_path.data(), path_len);

        uint64_t file_size = 4;
        out.write(reinterpret_cast<char*>(&file_size), 8);
        out.write("evil", 4);

        uint16_t end_marker = 0;
        out.write(reinterpret_cast<char*>(&end_marker), 2);
    }

    bool caught = false;
    try {
        unpack_directory(bad_archive, unpack_dir);
    } catch (const CryptoException& e) {
        if (e.get_code() == ErrorCode::CORRUPTED_FILE) caught = true;
    }

    TEST_ASSERT(caught, "archive with path traversal must be rejected");
    TEST_ASSERT(!is_regular_file("escaped.txt"), "escaped file must never be written");

    remove_file(bad_archive);
    remove_rf(unpack_dir);
}

void test_archive_path_length_limit() {
    const std::string bad_archive = "test_long_path.mcda";
    const std::string unpack_dir = "test_long_path_dir";

    // A malicious header must be rejected before trying to read its path bytes.
    {
        std::ofstream out(bad_archive, std::ios::binary);
        uint32_t magic = ARCHIVE_MAGIC;
        uint32_t ver = ARCHIVE_VERSION;
        out.write(reinterpret_cast<char*>(&magic), 4);
        out.write(reinterpret_cast<char*>(&ver), 4);

        uint16_t path_len = ARCHIVE_MAX_PATH_LEN + 1;
        out.write(reinterpret_cast<char*>(&path_len), 2);
    }

    bool caught = false;
    try {
        unpack_directory(bad_archive, unpack_dir);
    } catch (const CryptoException& e) {
        if (e.get_code() == ErrorCode::CORRUPTED_FILE) caught = true;
    }

    TEST_ASSERT(caught, "archive path longer than 4096 bytes must be rejected");

    remove_file(bad_archive);
    remove_rf(unpack_dir);
}

// ── Main ─────────────────────────────────────────────────────────────────────

int main() {
    if (sodium_init() < 0) {
        std::cerr << "libsodium initialization failed\n";
        return 1;
    }

    std::cout << "========================================\n";
    std::cout << "   MiniCrypto v2.1 Test Suite\n";
    std::cout << "========================================\n";

    RUN_TEST(test_secure_memory);
    RUN_TEST(test_header_validation);
    RUN_TEST(test_standard_encryption_roundtrip);
    RUN_TEST(test_split_key_mode);
    RUN_TEST(test_key_only_mode);
    RUN_TEST(test_headerless_mode);
    RUN_TEST(test_deterministic_mode);
    RUN_TEST(test_tamper_detection);
    RUN_TEST(test_wrong_password);
    RUN_TEST(test_large_file_streaming);
    RUN_TEST(test_empty_file);
    RUN_TEST(test_directory_pack_unpack);
    RUN_TEST(test_directory_encryption_roundtrip);
    RUN_TEST(test_path_traversal_prevention);
    RUN_TEST(test_archive_path_length_limit);
    RUN_TEST(test_atomic_file);

    std::cout << "========================================\n";
    std::cout << "Results: " << g_tests_passed << " passed, "
              << g_tests_failed << " failed.\n";
    std::cout << "========================================\n";

    return (g_tests_failed == 0) ? 0 : 1;
}
