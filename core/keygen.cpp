#include "keygen.h"
#include "format.h"
#include "crypto.h"
#include <argon2.h>
#include <sodium.h>
#include <cstring>

namespace minicrypto {

void derive_key_standard(
    const SecureString& password,
    const unsigned char* salt,
    uint32_t argon_time,
    uint32_t argon_mem_kb,
    uint32_t argon_threads,
    unsigned char* key_out)
{
    int result = argon2id_hash_raw(
        argon_time, argon_mem_kb, argon_threads,
        password.c_str(), password.size(),
        salt, SALT_LEN,
        key_out, KEY_LEN
    );
    
    if (result != ARGON2_OK) {
        throw CryptoException(ErrorCode::CRYPTO_OPERATION_FAILED,
            "Argon2id key derivation failed");
    }
}

void derive_key_split(
    const SecureString& password,
    const std::vector<uint8_t>& keyfile,
    const unsigned char* salt,
    uint32_t argon_time,
    uint32_t argon_mem_kb,
    uint32_t argon_threads,
    unsigned char* key_out)
{
    std::vector<uint8_t> material;
    material.reserve(password.size() + keyfile.size());
    material.insert(material.end(), 
        reinterpret_cast<const uint8_t*>(password.c_str()), 
        reinterpret_cast<const uint8_t*>(password.c_str()) + password.size());
    material.insert(material.end(), keyfile.begin(), keyfile.end());
    
    int result = argon2id_hash_raw(
        argon_time, argon_mem_kb, argon_threads,
        material.data(), material.size(),
        salt, SALT_LEN,
        key_out, KEY_LEN
    );
    
    sodium_memzero(material.data(), material.size());
    
    if (result != ARGON2_OK) {
        throw CryptoException(ErrorCode::CRYPTO_OPERATION_FAILED,
            "Argon2id key derivation failed (split-key mode)");
    }
}

void derive_key_from_keyfile(
    const std::vector<uint8_t>& keyfile,
    const unsigned char* salt,
    unsigned char* key_out)
{
    crypto_generichash_state state;
    crypto_generichash_init(&state, nullptr, 0, KEY_LEN);
    
    crypto_generichash_update(&state, keyfile.data(), keyfile.size());
    crypto_generichash_update(&state, salt, SALT_LEN);
    
    const unsigned char context[] = "MINICRYPTO::KEY_ONLY::v1";
    crypto_generichash_update(&state, context, sizeof(context) - 1);
    
    crypto_generichash_final(&state, key_out, KEY_LEN);
}

void derive_nonce_headerless(
    const SecureString& password,
    const unsigned char* salt,
    unsigned char* nonce_out)
{
    crypto_generichash_state state;
    crypto_generichash_init(&state, nullptr, 0, NONCE_LEN);
    
    crypto_generichash_update(&state, 
        reinterpret_cast<const unsigned char*>(password.c_str()), 
        password.size());
    
    crypto_generichash_update(&state, salt, SALT_LEN);
    
    crypto_generichash_update(&state,
        reinterpret_cast<const unsigned char*>(DOMAIN_HEADERLESS_NONCE),
        std::strlen(DOMAIN_HEADERLESS_NONCE));
    
    crypto_generichash_final(&state, nonce_out, NONCE_LEN);
}

void derive_deterministic_prekey(
    const SecureString& password,
    unsigned char* prekey_out)
{
    const uint32_t PREKEY_TIME = 5;
    const uint32_t PREKEY_MEM = 256 * 1024;
    const uint32_t PREKEY_THREADS = 2;
    
    const unsigned char FIXED_SALT[32] = {
        0x4D, 0x69, 0x6E, 0x69, 0x43, 0x72, 0x79, 0x70,
        0x74, 0x6F, 0x3A, 0x44, 0x65, 0x74, 0x65, 0x72,
        0x6D, 0x69, 0x6E, 0x69, 0x73, 0x74, 0x69, 0x63,
        0x53, 0x61, 0x6C, 0x74, 0x46, 0x69, 0x78, 0x65
    };
    
    int result = argon2id_hash_raw(
        PREKEY_TIME, PREKEY_MEM, PREKEY_THREADS,
        password.c_str(), password.size(),
        FIXED_SALT, sizeof(FIXED_SALT),
        prekey_out, 32
    );
    
    if (result != ARGON2_OK) {
        throw CryptoException(ErrorCode::CRYPTO_OPERATION_FAILED,
            "Argon2id deterministic pre-key derivation failed");
    }
}

void derive_deterministic_salt(
    const unsigned char* file_hash,
    const unsigned char* prekey,
    unsigned char* salt_out)
{
    crypto_generichash_state state;
    crypto_generichash_init(&state, nullptr, 0, SALT_LEN);
    
    crypto_generichash_update(&state, file_hash, 32);
    crypto_generichash_update(&state, prekey, 32);
    
    crypto_generichash_update(&state,
        reinterpret_cast<const unsigned char*>(DOMAIN_DETERMINISTIC_SALT),
        std::strlen(DOMAIN_DETERMINISTIC_SALT));
    
    crypto_generichash_final(&state, salt_out, SALT_LEN);
}

void derive_key(
    const SecureString& password,
    const unsigned char* salt,
    EncryptionMode mode,
    uint32_t argon_time,
    uint32_t argon_mem_kb,
    uint32_t argon_threads,
    const std::vector<uint8_t>* keyfile,
    unsigned char* key_out)
{
    switch (mode) {
    case EncryptionMode::STANDARD:
        derive_key_standard(password, salt, 
            argon_time, argon_mem_kb, argon_threads, key_out);
        break;
        
    case EncryptionMode::SPLIT_KEY:
        if (!keyfile) {
            throw CryptoException(ErrorCode::INVALID_MODE, 
                "SPLIT_KEY mode requires keyfile");
        }
        derive_key_split(password, *keyfile, salt, 
            argon_time, argon_mem_kb, argon_threads, key_out);
        break;
        
    case EncryptionMode::KEY_ONLY:
        if (!keyfile) {
            throw CryptoException(ErrorCode::INVALID_MODE, 
                "KEY_ONLY mode requires keyfile");
        }
        derive_key_from_keyfile(*keyfile, salt, key_out);
        break;
        
    case EncryptionMode::HEADERLESS:
        if (keyfile) {
            derive_key_split(password, *keyfile, salt, 
                argon_time, argon_mem_kb, argon_threads, key_out);
        } else {
            derive_key_standard(password, salt, 
                argon_time, argon_mem_kb, argon_threads, key_out);
        }
        break;
        
    default:
        throw CryptoException(ErrorCode::INVALID_MODE, "unknown encryption mode");
    }
}

}