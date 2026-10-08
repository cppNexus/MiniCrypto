#ifndef MINICRYPTO_KEYGEN_H
#define MINICRYPTO_KEYGEN_H

#include "secure_memory.h"
#include "crypto.h"
#include <vector>
#include <cstdint>

namespace minicrypto {

// Domain separation constants
constexpr const char* DOMAIN_DETERMINISTIC_PREKEY = "MINICRYPTO::DETERMINISTIC_PREKEY::v1";
constexpr const char* DOMAIN_DETERMINISTIC_SALT = "MINICRYPTO::DETERMINISTIC_SALT::v1";
constexpr const char* DOMAIN_HEADERLESS_NONCE = "MINICRYPTO::HEADERLESS_NONCE::v1";

// Mode 1: STANDARD
void derive_key_standard(
    const SecureString& password,
    const unsigned char* salt,
    uint32_t argon_time,
    uint32_t argon_mem_kb,
    uint32_t argon_threads,
    unsigned char* key_out
);

// Mode 2: SPLIT-KEY
void derive_key_split(
    const SecureString& password,
    const std::vector<uint8_t>& keyfile,
    const unsigned char* salt,
    uint32_t argon_time,
    uint32_t argon_mem_kb,
    uint32_t argon_threads,
    unsigned char* key_out
);

// Mode 3: KEY-ONLY
void derive_key_from_keyfile(
    const std::vector<uint8_t>& keyfile,
    const unsigned char* salt,
    unsigned char* key_out
);

// Mode 4: HEADERLESS
void derive_nonce_headerless(
    const SecureString& password,
    const unsigned char* salt,
    unsigned char* nonce_out
);

// DETERMINISTIC MODE
void derive_deterministic_prekey(
    const SecureString& password,
    unsigned char* prekey_out
);

void derive_deterministic_salt(
    const unsigned char* file_hash,
    const unsigned char* prekey,
    unsigned char* salt_out
);

// Unified interface
void derive_key(
    const SecureString& password,
    const unsigned char* salt,
    EncryptionMode mode,
    uint32_t argon_time,
    uint32_t argon_mem_kb,
    uint32_t argon_threads,
    const std::vector<uint8_t>* keyfile,
    unsigned char* key_out
);

}

#endif