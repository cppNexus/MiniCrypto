#include "deniable.h"
#include "crypto.h"
#include "format.h"
#include "keygen.h"

#include <sodium.h>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <cstdio>
#include <fstream>
#include <limits>
#include <ostream>
#include <streambuf>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h>
#include <io.h>
#include <fcntl.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace minicrypto {
namespace {

constexpr size_t SLOT_SALT_LEN = SALT_LEN;
constexpr size_t SLOT_NONCE_LEN = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
constexpr size_t SLOT_TAG_LEN = crypto_aead_xchacha20poly1305_ietf_ABYTES;
constexpr size_t LENGTH_FIELD_LEN = sizeof(uint64_t);
constexpr uint64_t MIN_SLOT_SIZE = SLOT_SALT_LEN + SLOT_NONCE_LEN + SLOT_TAG_LEN
                                 + LENGTH_FIELD_LEN;
constexpr uint64_t MAX_SLOT_SIZE = 64ULL * 1024ULL * 1024ULL;
constexpr uint32_t MAX_ARGON_TIME = 20;
constexpr uint32_t MAX_ARGON_MEM_KB = 1U << 18; // 256 MiB; defaults are 128 MiB
constexpr uint32_t MAX_ARGON_THREADS = 16;

constexpr char SLOT_KEY_DOMAIN[] = "MINICRYPTO::DENIABLE_SLOT_KEY::v1";
constexpr char SLOT_AAD_DOMAIN[] = "MINICRYPTO::DENIABLE_SLOT_AAD::v1";

enum class SlotRole : uint8_t { COVER = 0x43, HIDDEN = 0x48 };

class FileStreamBuffer final : public std::streambuf {
    FILE* file_ = nullptr;
protected:
    int_type overflow(int_type ch) override {
        if (traits_type::eq_int_type(ch, traits_type::eof())) {
            return traits_type::not_eof(ch);
        }
        return std::fputc(traits_type::to_char_type(ch), file_) == EOF
            ? traits_type::eof() : ch;
    }

    std::streamsize xsputn(const char* data, std::streamsize size) override {
        if (size <= 0) return 0;
        return static_cast<std::streamsize>(
            std::fwrite(data, 1, static_cast<size_t>(size), file_));
    }

    int sync() override {
        return std::fflush(file_) == 0 ? 0 : -1;
    }
public:
    void attach(FILE* file) noexcept { file_ = file; }
};

// Dedicated private atomic writer for this format. Plaintext output must not
// use AtomicFile's predictable .tmp name or its destructive replacement path.
class PrivateAtomicFile {
    std::filesystem::path final_path_;
    std::filesystem::path temp_path_;
    FILE* file_ = nullptr;
    FileStreamBuffer buffer_;
    std::ostream stream_;
    bool committed_ = false;

    static FILE* create_exclusive(const std::filesystem::path& path, bool& exists) {
        exists = false;
#ifdef _WIN32
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return nullptr;
        DWORD info_size = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &info_size);
        std::vector<unsigned char> token_info(info_size);
        if (info_size == 0 || !GetTokenInformation(token, TokenUser,
                token_info.data(), info_size, &info_size)) {
            CloseHandle(token);
            return nullptr;
        }
        CloseHandle(token);
        auto* user = reinterpret_cast<TOKEN_USER*>(token_info.data());

        EXPLICIT_ACCESSW entry{};
        entry.grfAccessPermissions = GENERIC_ALL;
        entry.grfAccessMode = SET_ACCESS;
        entry.grfInheritance = NO_INHERITANCE;
        entry.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        entry.Trustee.TrusteeType = TRUSTEE_IS_USER;
        entry.Trustee.ptstrName = static_cast<LPWSTR>(user->User.Sid);
        PACL dacl = nullptr;
        if (SetEntriesInAclW(1, &entry, nullptr, &dacl) != ERROR_SUCCESS) return nullptr;

        SECURITY_DESCRIPTOR descriptor;
        SECURITY_ATTRIBUTES attributes{sizeof(attributes), &descriptor, FALSE};
        const bool descriptor_ok = InitializeSecurityDescriptor(
                &descriptor, SECURITY_DESCRIPTOR_REVISION) &&
            SetSecurityDescriptorDacl(&descriptor, TRUE, dacl, FALSE) &&
            SetSecurityDescriptorControl(&descriptor, SE_DACL_PROTECTED, SE_DACL_PROTECTED);
        if (!descriptor_ok) {
            LocalFree(dacl);
            return nullptr;
        }

        HANDLE handle = CreateFileW(path.c_str(), GENERIC_WRITE, 0, &attributes,
            CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY, nullptr);
        const DWORD error = GetLastError();
        LocalFree(dacl);
        if (handle == INVALID_HANDLE_VALUE) {
            exists = error == ERROR_FILE_EXISTS || error == ERROR_ALREADY_EXISTS;
            return nullptr;
        }
        const int fd = _open_osfhandle(reinterpret_cast<intptr_t>(handle),
                                        _O_WRONLY | _O_BINARY);
        if (fd < 0) {
            CloseHandle(handle);
            DeleteFileW(path.c_str());
            return nullptr;
        }
        FILE* file = _fdopen(fd, "wb");
        if (!file) {
            _close(fd);
            DeleteFileW(path.c_str());
        }
        return file;
#else
        int flags = O_CREAT | O_EXCL | O_WRONLY;
#ifdef O_NOFOLLOW
        flags |= O_NOFOLLOW;
#endif
        const int fd = ::open(path.c_str(), flags, S_IRUSR | S_IWUSR);
        if (fd < 0) {
            exists = errno == EEXIST;
            return nullptr;
        }
        FILE* file = fdopen(fd, "wb");
        if (!file) {
            ::close(fd);
            std::error_code ec;
            std::filesystem::remove(path, ec);
        }
        return file;
#endif
    }

public:
    explicit PrivateAtomicFile(const std::filesystem::path& path)
        : final_path_(path), stream_(&buffer_) {
        const auto parent = final_path_.parent_path().empty()
            ? std::filesystem::path(".") : final_path_.parent_path();
        for (unsigned int attempt = 0; attempt < 16; ++attempt) {
            unsigned char random_suffix[16];
            char suffix[33];
            randombytes_buf(random_suffix, sizeof(random_suffix));
            sodium_bin2hex(suffix, sizeof(suffix), random_suffix, sizeof(random_suffix));
            temp_path_ = parent / std::filesystem::u8path(
                final_path_.filename().u8string() + ".tmp." + suffix);
            bool already_exists = false;
            file_ = create_exclusive(temp_path_, already_exists);
            if (file_) break;
            if (!already_exists) {
                throw CryptoException(ErrorCode::PERMISSION_DENIED,
                    "cannot create private temporary output in: " + parent.u8string());
            }
        }
        if (!file_) {
            throw CryptoException(ErrorCode::IO_ERROR,
                "could not allocate a unique private temporary output path");
        }
        buffer_.attach(file_);
    }

    ~PrivateAtomicFile() {
        if (file_) std::fclose(file_);
        if (!committed_) {
            std::error_code ec;
            std::filesystem::remove(temp_path_, ec);
        }
    }

    std::ostream& get() noexcept { return stream_; }

    void commit() {
        stream_.flush();
        if (!stream_ || std::fflush(file_) != 0) {
            throw CryptoException(ErrorCode::IO_ERROR,
                "flush failed before deniable-container commit");
        }
#ifdef _WIN32
        if (_commit(_fileno(file_)) != 0) {
            throw CryptoException(ErrorCode::IO_ERROR,
                "sync failed before deniable-container commit");
        }
#else
        if (::fsync(fileno(file_)) != 0) {
            throw CryptoException(ErrorCode::IO_ERROR,
                "sync failed before deniable-container commit");
        }
#endif
        if (std::fclose(file_) != 0) {
            file_ = nullptr;
            throw CryptoException(ErrorCode::IO_ERROR,
                "close failed before deniable-container commit");
        }
        file_ = nullptr;

#ifdef _WIN32
        if (!MoveFileExW(temp_path_.c_str(), final_path_.c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            throw CryptoException(ErrorCode::PERMISSION_DENIED,
                "cannot atomically publish deniable-container output");
        }
#else
        if (::rename(temp_path_.c_str(), final_path_.c_str()) != 0) {
            throw CryptoException(ErrorCode::PERMISSION_DENIED,
                "cannot atomically publish deniable-container output");
        }
        const int dir_fd = ::open(final_path_.parent_path().empty()
                ? "." : final_path_.parent_path().c_str(), O_RDONLY
#ifdef O_DIRECTORY
                | O_DIRECTORY
#endif
        );
        if (dir_fd >= 0) {
            (void)::fsync(dir_fd);
            ::close(dir_fd);
        }
#endif
        committed_ = true;
    }
};

static void validate_options(const DeniableContainerOptions& options) {
    if (options.slot_size_bytes < MIN_SLOT_SIZE || options.slot_size_bytes > MAX_SLOT_SIZE) {
        throw CryptoException(ErrorCode::INVALID_MODE,
            "deniable slot size is outside the supported range");
    }
    if (options.argon_time == 0 || options.argon_time > MAX_ARGON_TIME ||
        options.argon_mem_kb < 8192 || options.argon_mem_kb > MAX_ARGON_MEM_KB ||
        options.argon_threads == 0 || options.argon_threads > MAX_ARGON_THREADS) {
        throw CryptoException(ErrorCode::INVALID_MODE,
            "invalid deniable-container Argon2id parameters");
    }
}

static std::filesystem::path normalized_path(const std::filesystem::path& path) {
    std::error_code ec;
    auto result = std::filesystem::weakly_canonical(path, ec);
    if (!ec) return result;
    return std::filesystem::absolute(path).lexically_normal();
}

static void reject_alias(const std::filesystem::path& input,
                         const std::filesystem::path& output) {
    if (normalized_path(input) == normalized_path(output)) {
        throw CryptoException(ErrorCode::INVALID_MODE,
            "input and output paths must be different");
    }
}

static std::vector<unsigned char> read_payload(const std::filesystem::path& path,
                                                size_t max_size) {
    std::error_code ec;
    const uintmax_t file_size = std::filesystem::file_size(path, ec);
    if (ec) {
        throw CryptoException(ErrorCode::FILE_NOT_FOUND,
            "cannot determine input size: " + path.u8string());
    }
    if (file_size > max_size || file_size > std::numeric_limits<size_t>::max()) {
        throw CryptoException(ErrorCode::INVALID_MODE,
            "input exceeds deniable slot payload capacity: " + path.u8string());
    }

    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw CryptoException(ErrorCode::FILE_NOT_FOUND,
            "cannot open input: " + path.u8string());
    }
    std::vector<unsigned char> bytes(static_cast<size_t>(file_size));
    if (!bytes.empty()) {
        input.read(reinterpret_cast<char*>(bytes.data()),
                   static_cast<std::streamsize>(bytes.size()));
        if (input.gcount() != static_cast<std::streamsize>(bytes.size()) || input.bad()) {
            sodium_memzero(bytes.data(), bytes.size());
            throw CryptoException(ErrorCode::IO_ERROR,
                "failed to read input: " + path.u8string());
        }
    }
    return bytes;
}

static void encode_length(uint64_t length, unsigned char* out) {
    for (size_t i = 0; i < LENGTH_FIELD_LEN; ++i) {
        out[i] = static_cast<unsigned char>((length >> (i * 8)) & 0xffU);
    }
}

static uint64_t decode_length(const unsigned char* in) {
    uint64_t length = 0;
    for (size_t i = 0; i < LENGTH_FIELD_LEN; ++i) {
        length |= static_cast<uint64_t>(in[i]) << (i * 8);
    }
    return length;
}

static std::vector<unsigned char> make_aad(SlotRole role, uint64_t slot_size) {
    std::vector<unsigned char> aad(sizeof(SLOT_AAD_DOMAIN) - 1 + 1 + 8);
    size_t offset = 0;
    std::memcpy(aad.data(), SLOT_AAD_DOMAIN, sizeof(SLOT_AAD_DOMAIN) - 1);
    offset += sizeof(SLOT_AAD_DOMAIN) - 1;
    aad[offset++] = static_cast<unsigned char>(role);
    for (size_t i = 0; i < 8; ++i) {
        aad[offset + i] = static_cast<unsigned char>((slot_size >> (i * 8)) & 0xffU);
    }
    return aad;
}

static void derive_slot_key(const SecureString& password,
                            const unsigned char* salt,
                            SlotRole role,
                            const DeniableContainerOptions& options,
                            unsigned char* key_out) {
    SecureBuffer master_key(KEY_LEN);
    derive_key_standard(password, salt, options.argon_time, options.argon_mem_kb,
                        options.argon_threads, master_key.data());

    crypto_generichash_state state;
    if (crypto_generichash_init(&state, master_key.data(), KEY_LEN, KEY_LEN) != 0) {
        throw CryptoException(ErrorCode::CRYPTO_INIT_FAILED,
            "deniable slot key derivation initialization failed");
    }
    crypto_generichash_update(
        &state, reinterpret_cast<const unsigned char*>(SLOT_KEY_DOMAIN),
        sizeof(SLOT_KEY_DOMAIN) - 1);
    const unsigned char role_byte = static_cast<unsigned char>(role);
    crypto_generichash_update(&state, &role_byte, sizeof(role_byte));
    if (crypto_generichash_final(&state, key_out, KEY_LEN) != 0) {
        throw CryptoException(ErrorCode::CRYPTO_OPERATION_FAILED,
            "deniable slot key derivation failed");
    }
}

static std::vector<unsigned char> encrypt_slot(
    const std::vector<unsigned char>& payload,
    const SecureString& password,
    SlotRole role,
    const DeniableContainerOptions& options) {
    const size_t slot_size = static_cast<size_t>(options.slot_size_bytes);
    const size_t cipher_size = slot_size - SLOT_SALT_LEN - SLOT_NONCE_LEN;
    const size_t plain_size = cipher_size - SLOT_TAG_LEN;
    const size_t payload_capacity = plain_size - LENGTH_FIELD_LEN;

    if (payload.size() > payload_capacity) {
        throw CryptoException(ErrorCode::INVALID_MODE,
            "input exceeds deniable slot payload capacity");
    }

    std::vector<unsigned char> slot(slot_size);
    unsigned char* salt = slot.data();
    unsigned char* nonce = salt + SLOT_SALT_LEN;
    unsigned char* ciphertext = nonce + SLOT_NONCE_LEN;
    randombytes_buf(salt, SLOT_SALT_LEN);
    randombytes_buf(nonce, SLOT_NONCE_LEN);

    std::vector<unsigned char> plaintext(plain_size);
    BufferZeroGuard wipe_plaintext(plaintext.data(), plaintext.size());
    randombytes_buf(plaintext.data(), plaintext.size());
    encode_length(static_cast<uint64_t>(payload.size()), plaintext.data());
    if (!payload.empty()) {
        std::memcpy(plaintext.data() + LENGTH_FIELD_LEN, payload.data(), payload.size());
    }

    SecureBuffer key(KEY_LEN);
    derive_slot_key(password, salt, role, options, key.data());
    const std::vector<unsigned char> aad = make_aad(role, options.slot_size_bytes);
    unsigned long long cipher_written = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext, &cipher_written,
            plaintext.data(), static_cast<unsigned long long>(plaintext.size()),
            aad.data(), static_cast<unsigned long long>(aad.size()),
            nullptr, nonce, key.data()) != 0 || cipher_written != cipher_size) {
        throw CryptoException(ErrorCode::CRYPTO_OPERATION_FAILED,
            "deniable slot encryption failed");
    }
    return slot;
}

static std::vector<unsigned char> random_slot(uint64_t slot_size) {
    std::vector<unsigned char> slot(static_cast<size_t>(slot_size));
    randombytes_buf(slot.data(), slot.size());
    return slot;
}

static bool decrypt_slot(std::ifstream& input,
                         uint64_t offset,
                         uint64_t slot_size,
                         const SecureString& password,
                         SlotRole role,
                         const DeniableContainerOptions& options,
                         std::vector<unsigned char>& payload_out) {
    std::vector<unsigned char> slot(static_cast<size_t>(slot_size));
    input.clear();
    input.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    if (!input) return false;
    input.read(reinterpret_cast<char*>(slot.data()), static_cast<std::streamsize>(slot.size()));
    if (input.gcount() != static_cast<std::streamsize>(slot.size())) return false;

    const size_t cipher_size = slot.size() - SLOT_SALT_LEN - SLOT_NONCE_LEN;
    const size_t plain_size = cipher_size - SLOT_TAG_LEN;
    const unsigned char* salt = slot.data();
    const unsigned char* nonce = salt + SLOT_SALT_LEN;
    const unsigned char* ciphertext = nonce + SLOT_NONCE_LEN;

    SecureBuffer key(KEY_LEN);
    derive_slot_key(password, salt, role, options, key.data());
    std::vector<unsigned char> plaintext(plain_size);
    BufferZeroGuard wipe_plaintext(plaintext.data(), plaintext.size());
    const std::vector<unsigned char> aad = make_aad(role, slot_size);
    unsigned long long plaintext_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.data(), &plaintext_len, nullptr,
            ciphertext, static_cast<unsigned long long>(cipher_size),
            aad.data(), static_cast<unsigned long long>(aad.size()),
            nonce, key.data()) != 0 || plaintext_len != plain_size) {
        return false;
    }

    const uint64_t decoded_len = decode_length(plaintext.data());
    const uint64_t capacity = static_cast<uint64_t>(plain_size - LENGTH_FIELD_LEN);
    if (decoded_len > capacity || decoded_len > std::numeric_limits<size_t>::max()) {
        return false;
    }
    payload_out.assign(plaintext.begin() + static_cast<std::ptrdiff_t>(LENGTH_FIELD_LEN),
                       plaintext.begin() + static_cast<std::ptrdiff_t>(LENGTH_FIELD_LEN + decoded_len));
    return true;
}

static bool same_password(const SecureString& lhs, const SecureString& rhs) {
    return lhs.size() == rhs.size() &&
        sodium_memcmp(lhs.data(), rhs.data(), lhs.size()) == 0;
}

class VectorWiper {
    std::vector<unsigned char>& bytes_;
public:
    explicit VectorWiper(std::vector<unsigned char>& bytes) : bytes_(bytes) {}
    ~VectorWiper() {
        if (!bytes_.empty()) sodium_memzero(bytes_.data(), bytes_.size());
    }
    VectorWiper(const VectorWiper&) = delete;
    VectorWiper& operator=(const VectorWiper&) = delete;
};

} // namespace

void create_deniable_container(
    const std::filesystem::path& cover_input,
    const std::filesystem::path* hidden_input,
    const std::filesystem::path& output_path,
    const SecureString& cover_password,
    const SecureString* hidden_password,
    const DeniableContainerOptions& options) {
    if (sodium_init() < 0) {
        throw CryptoException(ErrorCode::CRYPTO_INIT_FAILED, "libsodium initialization failed");
    }
    validate_options(options);
    if (cover_password.empty()) {
        throw CryptoException(ErrorCode::INVALID_MODE, "cover password must not be empty");
    }
    if ((hidden_input == nullptr) != (hidden_password == nullptr)) {
        throw CryptoException(ErrorCode::INVALID_MODE,
            "hidden input and hidden password must be provided together");
    }
    reject_alias(cover_input, output_path);
    if (hidden_input) {
        reject_alias(*hidden_input, output_path);
        reject_alias(cover_input, *hidden_input);
        if (hidden_password->empty() || same_password(cover_password, *hidden_password)) {
            throw CryptoException(ErrorCode::INVALID_MODE,
                "cover and hidden passwords must be non-empty and different");
        }
    }

    const size_t plaintext_capacity = static_cast<size_t>(options.slot_size_bytes)
        - SLOT_SALT_LEN - SLOT_NONCE_LEN - SLOT_TAG_LEN - LENGTH_FIELD_LEN;
    std::vector<unsigned char> cover = read_payload(cover_input, plaintext_capacity);
    BufferZeroGuard wipe_cover(cover.data(), cover.size());
    std::vector<unsigned char> cover_slot = encrypt_slot(
        cover, cover_password, SlotRole::COVER, options);

    std::vector<unsigned char> hidden_slot;
    if (hidden_input) {
        std::vector<unsigned char> hidden = read_payload(*hidden_input, plaintext_capacity);
        BufferZeroGuard wipe_hidden(hidden.data(), hidden.size());
        hidden_slot = encrypt_slot(hidden, *hidden_password, SlotRole::HIDDEN, options);
    } else {
        hidden_slot = random_slot(options.slot_size_bytes);
    }

    PrivateAtomicFile output(output_path);
    std::ostream& stream = output.get();
    stream.write(reinterpret_cast<const char*>(cover_slot.data()),
                 static_cast<std::streamsize>(cover_slot.size()));
    stream.write(reinterpret_cast<const char*>(hidden_slot.data()),
                 static_cast<std::streamsize>(hidden_slot.size()));
    if (!stream) {
        throw CryptoException(ErrorCode::IO_ERROR, "failed to write deniable container");
    }
    output.commit();
}

void open_deniable_container(
    const std::filesystem::path& input_path,
    const std::filesystem::path& output_path,
    const SecureString& password,
    const DeniableContainerOptions& options) {
    if (sodium_init() < 0) {
        throw CryptoException(ErrorCode::CRYPTO_INIT_FAILED, "libsodium initialization failed");
    }
    if (password.empty()) {
        throw CryptoException(ErrorCode::AUTH_FAILED, "authentication failed");
    }
    reject_alias(input_path, output_path);

    std::ifstream input(input_path, std::ios::binary);
    if (!input) {
        throw CryptoException(ErrorCode::FILE_NOT_FOUND,
            "cannot open deniable container: " + input_path.u8string());
    }
    input.seekg(0, std::ios::end);
    const std::streamoff end = input.tellg();
    if (end < 0 || (end % 2) != 0) {
        throw CryptoException(ErrorCode::CORRUPTED_FILE, "invalid deniable container size");
    }
    const uint64_t slot_size = static_cast<uint64_t>(end / 2);
    if (slot_size < MIN_SLOT_SIZE || slot_size > MAX_SLOT_SIZE) {
        throw CryptoException(ErrorCode::CORRUPTED_FILE,
            "deniable container slot size is outside the supported range");
    }
    DeniableContainerOptions effective = options;
    effective.slot_size_bytes = slot_size;
    validate_options(effective);

    const uint64_t hidden_offset = slot_size;
    std::vector<unsigned char> hidden_payload;
    std::vector<unsigned char> cover_payload;
    VectorWiper wipe_hidden(hidden_payload);
    VectorWiper wipe_cover(cover_payload);

    // Always pay for both KDF and authentication attempts. Do not reveal which
    // slot matched through a short-circuit in this code path.
    const bool hidden_ok = decrypt_slot(input, hidden_offset, slot_size, password,
        SlotRole::HIDDEN, effective, hidden_payload);
    const bool cover_ok = decrypt_slot(input, 0, slot_size, password,
        SlotRole::COVER, effective, cover_payload);
    if (hidden_ok == cover_ok) {
        throw CryptoException(ErrorCode::AUTH_FAILED, "authentication failed");
    }

    const auto& payload = hidden_ok ? hidden_payload : cover_payload;
    PrivateAtomicFile output(output_path);
    if (!payload.empty()) {
        output.get().write(reinterpret_cast<const char*>(payload.data()),
                           static_cast<std::streamsize>(payload.size()));
    }
    if (!output.get()) {
        throw CryptoException(ErrorCode::IO_ERROR, "failed to write decrypted output");
    }
    output.commit();
}

} // namespace minicrypto
