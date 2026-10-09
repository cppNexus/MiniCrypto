#ifndef MINICRYPTO_CRYPTO_H
#define MINICRYPTO_CRYPTO_H

#include "secure_memory.h"
#include <filesystem>
#include <string>
#include <vector>
#include <cstdint>
#include <functional>

namespace minicrypto {

// Error codes
enum class ErrorCode {
    OK = 0,
    FILE_NOT_FOUND,
    WRONG_PASSWORD,              // Deprecated: use AUTH_FAILED
    AUTH_FAILED,                 // Authentication failed (wrong password OR corrupted file)
    CORRUPTED_FILE,
    DISK_FULL,
    PERMISSION_DENIED,
    IO_ERROR,                    // Generic I/O error (read/write failure)
    CRYPTO_FAILURE,              // Deprecated: use more specific codes below
    CRYPTO_INIT_FAILED,          // Stream initialization failed
    CRYPTO_OPERATION_FAILED,     // Encryption/decryption operation failed
    VERIFICATION_FAILED,
    MEMORY_LOCK_FAILED,
    INVALID_MODE,
    DETERMINISTIC_MODE_DECLINED  // User declined deterministic warning
};

// Encryption modes
enum class EncryptionMode {
    STANDARD,      // password → Argon2id → key, header with params
    SPLIT_KEY,     // password + keyfile → Argon2id → key
    KEY_ONLY,      // keyfile only (no password)
    HEADERLESS     // minimal header (salt only), nonce derived from stream
};

// Exception class
class CryptoException : public std::exception {
    ErrorCode code_;
    std::string msg_;

public:
    CryptoException(ErrorCode code, const std::string& msg);
    const char* what() const noexcept override { return msg_.c_str(); }
    ErrorCode get_code() const { return code_; }
};

// Encryption parameters
struct EncryptParams {
    EncryptionMode mode = EncryptionMode::STANDARD;
    uint32_t argon_time = 3;
    uint32_t argon_mem_kb = 1 << 17;  // 128 MB
    uint32_t argon_threads = 2;

    // Optional keyfile data
    const std::vector<uint8_t>* keyfile = nullptr;

    // FOOTGUN MODE: Deterministic salt derivation
    bool deterministic_salt = false;

    // If deterministic_salt=true, this callback is called for confirmation
    std::function<bool(void)> deterministic_confirm_callback;

    // Progress callback: (bytes_processed) -> void
    std::function<void(uint64_t)> progress_callback;
};

// Decryption parameters
struct DecryptParams {
    EncryptionMode mode = EncryptionMode::STANDARD;

    // For STANDARD mode: read from header
    // For HEADERLESS/KEY_ONLY: must be provided
    uint32_t argon_time = 3;
    uint32_t argon_mem_kb = 1 << 17;
    uint32_t argon_threads = 2;

    const std::vector<uint8_t>* keyfile = nullptr;
    std::function<void(uint64_t)> progress_callback;
};

// File metadata (from header or estimated)
struct FileMetadata {
    EncryptionMode mode;
    uint64_t plaintext_size;  // 0 if unknown (headerless)
    uint32_t argon_time;
    uint32_t argon_mem_kb;
    uint32_t argon_threads;
    bool has_full_header;
};

// === CORE API ===

void encrypt_file(
    const std::filesystem::path& input_path,
    const std::filesystem::path& output_path,
    const SecureString& password,
    const EncryptParams& params
);

void decrypt_file(
    const std::filesystem::path& input_path,
    const std::filesystem::path& output_path,
    const SecureString& password,
    const DecryptParams& params
);

bool verify_encryption(
    const std::filesystem::path& original_path,
    const std::filesystem::path& encrypted_path,
    const SecureString& password,
    const DecryptParams& params
);

FileMetadata read_metadata(const std::filesystem::path& path);

bool self_test();

} // namespace minicrypto

#endif // MINICRYPTO_CRYPTO_H