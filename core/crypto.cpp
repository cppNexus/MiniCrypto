#include "../core/crypto.h"
#include "../core/format.h"
#include "../core/keygen.h"
#include "../core/file_ops.h"
#include <sodium.h>
#include <fstream>
#include <vector>
#include <cstring>
#include <algorithm>
#include <filesystem>

namespace minicrypto {

static void remove_temp_file(const std::filesystem::path& path) {
    std::error_code ec;
    std::filesystem::remove(path, ec);
}

CryptoException::CryptoException(ErrorCode code, const std::string& msg)
    : code_(code), msg_(msg) {}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Read exactly `len` bytes or throw.
static void must_read(std::ifstream& fi, void* buf, size_t len,
                      ErrorCode ec, const char* msg) {
    fi.read(reinterpret_cast<char*>(buf), static_cast<std::streamsize>(len));
    if (fi.gcount() != static_cast<std::streamsize>(len)) {
        throw CryptoException(ec, msg);
    }
}

/// Write exactly `len` bytes or throw.
static void must_write(std::ofstream& fo, const void* buf, size_t len,
                       const char* context) {
    fo.write(reinterpret_cast<const char*>(buf), static_cast<std::streamsize>(len));
    if (!fo) {
        std::string msg = "write failed: ";
        msg += context;
        throw CryptoException(ErrorCode::IO_ERROR, msg);
    }
}

/// Compute SHA-256 of a file.
static void sha256_file(const std::filesystem::path& path, unsigned char* hash_out) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw CryptoException(ErrorCode::FILE_NOT_FOUND,
            "cannot open file for hashing: " + path.u8string());
    }

    crypto_hash_sha256_state state;
    crypto_hash_sha256_init(&state);

    std::vector<unsigned char> buffer(CHUNK_SIZE);
    while (file) {
        file.read(reinterpret_cast<char*>(buffer.data()),
                  static_cast<std::streamsize>(buffer.size()));
        std::streamsize got = file.gcount();
        if (got > 0) {
            crypto_hash_sha256_update(&state, buffer.data(),
                                      static_cast<unsigned long long>(got));
        }
    }

    crypto_hash_sha256_final(&state, hash_out);
}

// ── Public API ────────────────────────────────────────────────────────────────

void encrypt_file(
    const std::filesystem::path& input_path,
    const std::filesystem::path& output_path,
    const SecureString& password,
    const EncryptParams& params)
{
    // Validate mode
    if (params.mode == EncryptionMode::KEY_ONLY && !params.keyfile) {
        throw CryptoException(ErrorCode::INVALID_MODE,
            "KEY_ONLY mode requires keyfile");
    }

    // Deterministic mode: must be explicitly confirmed
    if (params.deterministic_salt) {
        if (!params.deterministic_confirm_callback) {
            throw CryptoException(ErrorCode::DETERMINISTIC_MODE_DECLINED,
                "deterministic mode requires explicit confirmation callback");
        }
        if (!params.deterministic_confirm_callback()) {
            throw CryptoException(ErrorCode::DETERMINISTIC_MODE_DECLINED,
                "deterministic mode declined by user");
        }
    }

    // Open input file
    std::ifstream fi(input_path, std::ios::binary);
    if (!fi) {
        throw CryptoException(ErrorCode::FILE_NOT_FOUND,
            "input file not found: " + input_path.u8string());
    }

    fi.seekg(0, std::ios::end);
    uint64_t fsize = static_cast<uint64_t>(fi.tellg());
    fi.seekg(0);

    // Build header
    Header h{};
    h.magic          = MAGIC;
    h.version        = VERSION_CURRENT;
    h.plaintext_size = fsize;
    h.argon_time     = params.argon_time;
    h.argon_mem_kb   = params.argon_mem_kb;
    h.argon_threads  = params.argon_threads;
    h.mode           = static_cast<uint8_t>(params.mode);
    h.kdf_version    = DOMAIN_VERSION_DETERMINISTIC;
    h.reserved       = 0;

    // Generate or derive salt
    if (params.deterministic_salt) {
        unsigned char file_hash[32];
        sha256_file(input_path, file_hash);

        unsigned char prekey[32];
        derive_deterministic_prekey(password, prekey);
        derive_deterministic_salt(file_hash, prekey, h.salt);

        sodium_memzero(file_hash, sizeof(file_hash));
        sodium_memzero(prekey,    sizeof(prekey));
    } else {
        randombytes_buf(h.salt, SALT_LEN);
    }

    // Derive encryption key
    SecureBuffer key_buf(KEY_LEN);
    derive_key(password, h.salt, params.mode,
               params.argon_time, params.argon_mem_kb, params.argon_threads,
               params.keyfile, key_buf.data());

    // Open output (atomic write)
    AtomicFile output(output_path);
    std::ofstream& fo = output.get();

    // Write header
    if (params.mode == EncryptionMode::HEADERLESS) {
        must_write(fo, h.salt, SALT_LEN, "salt");
    } else {
        must_write(fo, &h, sizeof(h), "header");
    }

    // Initialize secretstream
    crypto_secretstream_xchacha20poly1305_state st;
    unsigned char stream_header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

    if (params.deterministic_salt) {
        // Derive deterministic stream_header so ciphertext is completely reproducible
        crypto_generichash_state gst;
        crypto_generichash_init(&gst, nullptr, 0, crypto_secretstream_xchacha20poly1305_HEADERBYTES);
        crypto_generichash_update(&gst, h.salt, SALT_LEN);
        const unsigned char stream_ctx[] = "MINICRYPTO::DETERMINISTIC_STREAM::v1";
        crypto_generichash_update(&gst, stream_ctx, sizeof(stream_ctx) - 1);
        crypto_generichash_final(&gst, stream_header, sizeof(stream_header));

        if (crypto_secretstream_xchacha20poly1305_init_pull(&st, stream_header, key_buf.data()) != 0) {
            throw CryptoException(ErrorCode::CRYPTO_INIT_FAILED,
                "secretstream init failed");
        }
    } else {
        if (crypto_secretstream_xchacha20poly1305_init_push(
                &st, stream_header, key_buf.data()) != 0) {
            throw CryptoException(ErrorCode::CRYPTO_INIT_FAILED,
                "secretstream init failed");
        }
    }
    must_write(fo, stream_header, sizeof(stream_header), "stream header");

    // Encrypt in chunks (handles empty files by writing a 0-byte FINAL chunk)
    std::vector<unsigned char> plainbuf(CHUNK_SIZE);
    std::vector<unsigned char> cipherbuf(CHUNK_SIZE + TAG_LEN);

    uint64_t processed = 0;

    do {
        fi.read(reinterpret_cast<char*>(plainbuf.data()),
                static_cast<std::streamsize>(plainbuf.size()));
        std::streamsize got = fi.gcount();

        bool is_final = (fsize == 0) || (processed + static_cast<uint64_t>(got) >= fsize);
        unsigned char tag = is_final
            ? crypto_secretstream_xchacha20poly1305_TAG_FINAL
            : crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;

        unsigned long long cipherlen;
        if (crypto_secretstream_xchacha20poly1305_push(
                &st, cipherbuf.data(), &cipherlen,
                plainbuf.data(), static_cast<unsigned long long>(got),
                nullptr, 0, tag) != 0) {
            throw CryptoException(ErrorCode::CRYPTO_OPERATION_FAILED,
                "encryption failed");
        }

        must_write(fo, cipherbuf.data(), static_cast<size_t>(cipherlen), "ciphertext");

        processed += static_cast<uint64_t>(got);
        if (params.progress_callback && got > 0) params.progress_callback(processed);

        if (is_final) break;
    } while (true);

    if (fi.bad()) {
        throw CryptoException(ErrorCode::IO_ERROR, "read error during encryption");
    }

    output.commit();
}

void decrypt_file(
    const std::filesystem::path& input_path,
    const std::filesystem::path& output_path,
    const SecureString& password,
    const DecryptParams& params)
{
    std::ifstream fi(input_path, std::ios::binary);
    if (!fi) {
        throw CryptoException(ErrorCode::FILE_NOT_FOUND,
            "input file not found: " + input_path.u8string());
    }

    const bool headerless = (params.mode == EncryptionMode::HEADERLESS);

    Header h{};
    uint32_t argon_t = params.argon_time;
    uint32_t argon_m = params.argon_mem_kb;
    uint32_t argon_p = params.argon_threads;
    EncryptionMode mode;

    // Read header
    if (headerless) {
        must_read(fi, h.salt, SALT_LEN,
                  ErrorCode::CORRUPTED_FILE, "file too short (salt)");
        mode = EncryptionMode::HEADERLESS;
    } else {
        must_read(fi, &h, sizeof(h),
                  ErrorCode::CORRUPTED_FILE, "file too short (header)");

        HeaderStatus status = validate_header(h);
        if (status != HeaderStatus::VALID) {
            std::string err = "header validation failed: ";
            err += header_status_string(status);
            throw CryptoException(ErrorCode::CORRUPTED_FILE, err);
        }

        if (h.mode == static_cast<uint8_t>(EncryptionMode::HEADERLESS)) {
            throw CryptoException(ErrorCode::CORRUPTED_FILE,
                "file claims headerless mode but full header is present");
        }

        argon_t = h.argon_time;
        argon_m = h.argon_mem_kb;
        argon_p = h.argon_threads;
        mode    = static_cast<EncryptionMode>(h.mode);
    }

    // Derive decryption key
    SecureBuffer key_buf(KEY_LEN);
    derive_key(password, h.salt, mode, argon_t, argon_m, argon_p,
               params.keyfile, key_buf.data());

    // Read secretstream header
    unsigned char stream_header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    must_read(fi, stream_header, sizeof(stream_header),
              ErrorCode::CORRUPTED_FILE, "file too short (stream header)");

    // Initialize secretstream pull
    crypto_secretstream_xchacha20poly1305_state st;
    if (crypto_secretstream_xchacha20poly1305_init_pull(
            &st, stream_header, key_buf.data()) != 0) {
        throw CryptoException(ErrorCode::AUTH_FAILED,
            "invalid stream header — wrong password or corrupted file");
    }

    // Open output (atomic write)
    AtomicFile output(output_path);
    std::ofstream& fo = output.get();

    // Decrypt in chunks
    std::vector<unsigned char> cipherbuf(CHUNK_SIZE + TAG_LEN);
    std::vector<unsigned char> plainbuf(CHUNK_SIZE);

    uint64_t processed  = 0;
    bool     seen_final = false;

    while (true) {
        fi.read(reinterpret_cast<char*>(cipherbuf.data()),
                static_cast<std::streamsize>(cipherbuf.size()));
        std::streamsize got = fi.gcount();
        if (got == 0) break;

        unsigned long long plainlen;
        unsigned char      tag;

        if (crypto_secretstream_xchacha20poly1305_pull(
                &st, plainbuf.data(), &plainlen, &tag,
                cipherbuf.data(), static_cast<unsigned long long>(got),
                nullptr, 0) != 0) {
            throw CryptoException(ErrorCode::AUTH_FAILED,
                "authentication failed — wrong password or corrupted file");
        }

        if (plainlen > 0) {
            must_write(fo, plainbuf.data(), static_cast<size_t>(plainlen), "plaintext");
        }

        processed += plainlen;
        if (params.progress_callback) params.progress_callback(processed);

        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
            seen_final = true;
            break;
        }
    }

    if (!seen_final) {
        throw CryptoException(ErrorCode::CORRUPTED_FILE,
            "truncated encrypted stream — missing FINAL tag");
    }

    if (fi.bad()) {
        throw CryptoException(ErrorCode::IO_ERROR, "read error during decryption");
    }

    output.commit();
}

bool verify_encryption(
    const std::filesystem::path& original_path,
    const std::filesystem::path& encrypted_path,
    const SecureString& password,
    const DecryptParams& params)
{
    std::filesystem::path temp_decrypt = encrypted_path;
    temp_decrypt += ".verify_tmp";

    try {
        DecryptParams vp = params;
        if (vp.mode == EncryptionMode::HEADERLESS) {
            if (vp.argon_time    == 0) vp.argon_time    = ARGON_T_DEFAULT;
            if (vp.argon_mem_kb  == 0) vp.argon_mem_kb  = ARGON_M_DEFAULT;
            if (vp.argon_threads == 0) vp.argon_threads  = ARGON_P_DEFAULT;
        }

        decrypt_file(encrypted_path, temp_decrypt, password, vp);

        std::ifstream f1(original_path, std::ios::binary);
        std::ifstream f2(temp_decrypt,  std::ios::binary);

        if (!f1 || !f2) {
            remove_temp_file(temp_decrypt);
            return false;
        }

        std::vector<char> buf1(CHUNK_SIZE), buf2(CHUNK_SIZE);
        bool match = true;

        while (true) {
            f1.read(buf1.data(), static_cast<std::streamsize>(buf1.size()));
            f2.read(buf2.data(), static_cast<std::streamsize>(buf2.size()));

            auto got1 = f1.gcount();
            auto got2 = f2.gcount();

            if (got1 != got2 ||
                std::memcmp(buf1.data(), buf2.data(), static_cast<size_t>(got1)) != 0) {
                match = false;
                break;
            }

            if (got1 == 0) break;
        }

        remove_temp_file(temp_decrypt);
        return match;

    } catch (...) {
        remove_temp_file(temp_decrypt);
        throw;
    }
}

FileMetadata read_metadata(const std::filesystem::path& path) {
    std::ifstream fi(path, std::ios::binary);
    if (!fi) {
        throw CryptoException(ErrorCode::FILE_NOT_FOUND,
            "file not found: " + path.u8string());
    }

    Header h{};
    fi.read(reinterpret_cast<char*>(&h), sizeof(h));

    FileMetadata meta{};

    if (fi.gcount() == static_cast<std::streamsize>(sizeof(h)) && h.magic == MAGIC) {
        meta.has_full_header = true;
        meta.mode            = static_cast<EncryptionMode>(h.mode);
        meta.plaintext_size  = h.plaintext_size;
        meta.argon_time      = h.argon_time;
        meta.argon_mem_kb    = h.argon_mem_kb;
        meta.argon_threads   = h.argon_threads;
    } else {
        meta.has_full_header = false;
        meta.mode            = EncryptionMode::HEADERLESS;
        meta.plaintext_size  = 0;
        meta.argon_time      = ARGON_T_DEFAULT;
        meta.argon_mem_kb    = ARGON_M_DEFAULT;
        meta.argon_threads   = ARGON_P_DEFAULT;
    }

    return meta;
}

bool self_test() {
    const char* test_data = "The quick brown fox jumps over the lazy dog";
    SecureString test_pass("test_password_123", 17);

    const char* plain_tmp   = "minicrypto_selftest_plain.tmp";
    const char* enc_tmp     = "minicrypto_selftest_enc.tmp";
    const char* dec_tmp     = "minicrypto_selftest_dec.tmp";
    const char* wrong_tmp   = "minicrypto_selftest_wrong.tmp";

    auto cleanup = [&] {
        remove_temp_file(plain_tmp);
        remove_temp_file(enc_tmp);
        remove_temp_file(dec_tmp);
        remove_temp_file(wrong_tmp);
    };

    try {
        // Write plaintext
        {
            std::ofstream f(plain_tmp, std::ios::binary);
            f.write(test_data, static_cast<std::streamsize>(std::strlen(test_data)));
        }

        // Encrypt
        EncryptParams ep;
        ep.mode = EncryptionMode::STANDARD;
        encrypt_file(plain_tmp, enc_tmp, test_pass, ep);

        // Decrypt
        DecryptParams dp;
        dp.mode = EncryptionMode::STANDARD;
        decrypt_file(enc_tmp, dec_tmp, test_pass, dp);

        // Verify plaintext matches
        std::ifstream dec(dec_tmp, std::ios::binary);
        std::string result((std::istreambuf_iterator<char>(dec)),
                            std::istreambuf_iterator<char>());
        if (result != test_data) {
            cleanup();
            return false;
        }

        // Verify wrong password is rejected
        bool caught = false;
        try {
            SecureString wrong("wrong_password", 14);
            decrypt_file(enc_tmp, wrong_tmp, wrong, dp);
        } catch (const CryptoException& e) {
            if (e.get_code() == ErrorCode::AUTH_FAILED) caught = true;
        }
        if (!caught) {
            cleanup();
            return false;
        }

        cleanup();
        return true;

    } catch (...) {
        cleanup();
        return false;
    }
}

} // namespace minicrypto