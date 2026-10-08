#ifndef MINICRYPTO_FORMAT_H
#define MINICRYPTO_FORMAT_H

#include <cstdint>
#include <cstddef>
#include <sodium.h>

namespace minicrypto {

// File format constants
constexpr uint32_t MAGIC = 0x4D434332;  // "MCC2"

// Format version history:
// v1: Initial release (deprecated)
// v2: Current - added mode field, domain separation in KDF
constexpr uint8_t VERSION_CURRENT = 2;
constexpr uint8_t VERSION_MIN_SUPPORTED = 2;  // Don't decrypt v1 files

constexpr size_t SALT_LEN = 32;
constexpr size_t NONCE_LEN = 24;
constexpr size_t KEY_LEN = 32;

// CRITICAL FIX: secretstream uses 17 bytes for authentication tag, not 16!
constexpr size_t TAG_LEN = crypto_secretstream_xchacha20poly1305_ABYTES;  // 17 bytes

// Argon2 defaults
constexpr uint32_t ARGON_T_DEFAULT = 3;
constexpr uint32_t ARGON_M_DEFAULT = 1 << 17;  // 128 MB
constexpr uint32_t ARGON_P_DEFAULT = 2;

constexpr size_t CHUNK_SIZE = 1 << 20;  // 1 MB

// Domain separation versions
// CRITICAL: If you change KDF/hash algorithms, increment these versions!
// This ensures old files can still be decrypted with their original parameters.
constexpr uint8_t DOMAIN_VERSION_DETERMINISTIC = 1;
constexpr uint8_t DOMAIN_VERSION_HEADERLESS = 1;
constexpr uint8_t DOMAIN_VERSION_KEYONLY = 1;

// File header structure (v2)
// Full header: STANDARD, SPLIT_KEY, KEY_ONLY modes
// Minimal header: HEADERLESS mode (salt only, 32 bytes)
#pragma pack(push, 1)
struct Header {
    uint32_t magic;              // 0x4D434332 "MCC2"
    uint8_t version;             // Current: 2
    uint8_t mode;                // EncryptionMode enum value
    uint8_t kdf_version;         // KDF domain version (for future changes)
    uint8_t reserved;            // Future use
    uint64_t plaintext_size;     // Original file size
    uint32_t argon_time;         // Argon2 iterations
    uint32_t argon_mem_kb;       // Argon2 memory in KB
    uint32_t argon_threads;      // Argon2 parallelism
    unsigned char salt[SALT_LEN];    // 32 bytes
    unsigned char nonce[NONCE_LEN];  // 24 bytes (unused - secretstream generates its own)
};
#pragma pack(pop)

// Header validation result
enum class HeaderStatus {
    VALID,
    INVALID_MAGIC,
    UNSUPPORTED_VERSION,
    CORRUPTED
};

// Validate header and check version
HeaderStatus validate_header(const Header& h);

// Get human-readable error for header status
const char* header_status_string(HeaderStatus status);

} // namespace minicrypto

#endif // MINICRYPTO_FORMAT_H