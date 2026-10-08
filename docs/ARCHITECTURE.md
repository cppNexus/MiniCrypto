# MiniCrypto Architecture

##  Core Principles

### 1. Library-First Design
**Problem**: Original code had UI (ProgressBar) directly in crypto.cpp
**Solution**: Core library has ZERO UI dependencies

```cpp
// [FAIL] WRONG (old code)
void encrypt_file(...) {
    ProgressBar progress(fsize);  // UI IN CORE!
    progress.update(got);
}

// [PASS] CORRECT (new code)
void encrypt_file(..., const EncryptParams& params) {
    if (params.progress_callback) {
        params.progress_callback(processed);  // Optional callback
    }
}
```

**Benefits**:
- Core can be used as library
- No forced terminal output
- GUI wrappers possible
- Server integration possible
- Testing without UI noise

### 2. Mode-Based Architecture

**Problem**: `headerless` was just a boolean flag
**Solution**: Explicit `EncryptionMode` enum

```cpp
enum class EncryptionMode {
    STANDARD,      // password → Argon2id → key
    SPLIT_KEY,     // password + keyfile → Argon2id → key
    KEY_ONLY,      // keyfile → HKDF → key (no password)
    HEADERLESS     // derived nonce, minimal header
};
```

**Why This Matters**:
- Clear intent in code
- Type safety (can't mix modes accidentally)
- Easy to add new modes later
- Self-documenting API

### 3. Separation of Concerns

```
Core Library (libminicrypto_core)
├── crypto.cpp     - Encryption/decryption logic
├── keygen.cpp     - Key derivation functions
├── format.cpp     - File format handling
├── secure_memory.cpp - mlock, zeroize
└── file_ops.cpp   - Atomic writes, secure delete

CLI Wrapper (minicrypto executable)
├── main.cpp       - Argument parsing
└── ui.cpp         - Progress bars, prompts
```

**Boundaries**:
- Core NEVER calls UI
- UI NEVER implements crypto
- Clean dependency graph

##  Cryptographic Design

### Key Derivation Modes

#### 1. STANDARD
```
password → Argon2id → key
         ↓
      (salt from file)
```

#### 2. SPLIT-KEY
```
password + keyfile → Argon2id → key
                  ↓
               (salt from file)
```
**Use case**: USB key + password (two-factor)

#### 3. KEY-ONLY
```
keyfile → HKDF-BLAKE2b → key
       ↓
    (salt from file)
```
**Use case**: Automated systems, no password prompt
**Why HKDF instead of Argon2**: No password = no brute-force risk, skip expensive KDF

#### 4. HEADERLESS
```
password → Argon2id → key
         ↓
password + salt + "NONCE" → BLAKE2b → nonce (deterministic)
```
**Use case**: Steganography, deniability
**Header**: Only 16-byte salt, no magic number, no size, no parameters

### Nonce Strategy

| Mode | Nonce Source | Security Property |
|------|-------------|-------------------|
| STANDARD | Random (24 bytes) | Maximum entropy |
| SPLIT-KEY | Random (24 bytes) | Maximum entropy |
| KEY-ONLY | Random (24 bytes) | Maximum entropy |
| HEADERLESS | Derived from password+salt | Deterministic, allows minimal header |

**Why deterministic nonce for HEADERLESS?**
- Allows 16-byte header (salt only)
- Still secure: nonce derived from password (unknown to attacker)
- Enables deniable encryption (no magic number)

##  Build System Design

### Static vs Dynamic

```cmake
# Dynamic build (default)
cmake ..
make
# Links to system libsodium, libargon2

# Static build (air-gapped)
cmake .. -DBUILD_STATIC_CLI=ON
make
# Embeds everything, no runtime dependencies
```

**Why both?**
- Dynamic: Package managers, updates
- Static: Air-gapped systems, no dependencies

### Library-Only Build

```cmake
cmake .. -DBUILD_CLI=OFF
make install
# Installs only libminicrypto_core
```

**Use case**: Integrate into other projects

##  Security Decisions

### 1. Memory Management

```cpp
// [PASS] CORRECT
SecureBuffer key_buf(KEY_LEN);  // mlock'd, auto-zeroed
derive_key(..., key_buf.data(), ...);
// ~SecureBuffer() → sodium_memzero + munlock

// [FAIL] WRONG
unsigned char key[KEY_LEN];  // Can be swapped, not zeroed
```

**Why SecureBuffer?**
- RAII: automatic cleanup
- mlock: prevents swap
- sodium_memzero: compiler can't optimize away

### 2. Password Handling

```cpp
// [PASS] CORRECT
SecureString password = get_password_interactive(true);
encrypt_file(..., password, ...);
// ~SecureString() → sodium_memzero

// [FAIL] WRONG
std::string password;  // Copies everywhere, never truly deleted
```

**Why SecureString?**
- No std::string copies
- mlock'd vector
- Guaranteed zeroing on destruction

### 3. Atomic File Writes

```cpp
AtomicFile output(path);
output.get() << data;  // Write to .tmp
output.commit();       // Atomic rename
// If crash/exception: .tmp cleaned up, original untouched
```

**Why?**
- Never corrupt original on failure
- Disk-full handling
- Clean error recovery

### 4. Secure Deletion

```cpp
void secure_delete(const std::string& path) {
    // 3-pass overwrite: 0xFF → 0x00 → random
    // fsync() between passes
    // unlink()
}
```

**Limitations documented**:
- SSDs: wear-leveling
- CoW filesystems: snapshots
- Journaling: metadata

**Honest approach**: Document limitations, not false security

##  Anti-Patterns Avoided

### 1. No Implicit UI
```cpp
// [FAIL] BAD (old code)
void encrypt_file(...) {
    std::cout << "Encrypting..." << std::endl;  // Forces terminal
}

// [PASS] GOOD (new code)
void encrypt_file(..., params) {
    if (params.progress_callback) {
        params.progress_callback(bytes);  // Optional
    }
}
```

### 2. No Boolean Hell
```cpp
// [FAIL] BAD
encrypt_file(..., bool headerless, bool use_keyfile, bool split_mode);

// [PASS] GOOD
encrypt_file(..., EncryptionMode mode, const EncryptParams& params);
```

### 3. No Mixed Responsibilities
```cpp
// [FAIL] BAD
// crypto.cpp includes ui.h and calls UI functions

// [PASS] GOOD
// crypto.cpp only does crypto
// main.cpp calls crypto with progress callbacks
```

##  Data Flow

### Encryption

```
Input File
    ↓
[Read Plaintext] ← CHUNK_SIZE
    ↓
[Derive Key] ← Password + Salt (+ Keyfile if mode requires)
    ↓         (Argon2id or HKDF)
    ↓
[Generate/Derive Nonce] ← Random or Derived
    ↓
[Write Header] ← Full or Minimal (based on mode)
    ↓
[Init Stream] ← XChaCha20-Poly1305
    ↓
[Encrypt Chunks] ← secretstream API
    ↓           ← Progress callback if provided
    ↓
[Write Ciphertext]
    ↓
[Atomic Commit] ← .tmp → final
    ↓
[Optional Verify] ← Decrypt + Compare
    ↓
[Optional Secure Delete]
```

### Decryption

```
Input File
    ↓
[Read Header] ← Full or Minimal (based on mode)
    ↓
[Validate Magic] ← Skip if HEADERLESS
    ↓
[Derive Key] ← Password + Salt (+ Keyfile if mode requires)
    ↓
[Derive Nonce if HEADERLESS]
    ↓
[Init Stream] ← XChaCha20-Poly1305
    ↓
[Decrypt Chunks] ← secretstream API
    ↓            ← Verify MAC each chunk
    ↓            ← Progress callback if provided
    ↓
[Write Plaintext]
    ↓
[Atomic Commit]
```

##  Error Handling Philosophy

```cpp
// Specific error codes
enum class ErrorCode {
    OK,
    FILE_NOT_FOUND,
    WRONG_PASSWORD,
    CORRUPTED_FILE,
    INVALID_MODE,    // New: mode validation
    // ...
};

// Exceptions with context
throw CryptoException(ErrorCode::INVALID_MODE, 
    "KEY_ONLY mode requires keyfile");
```

**Why?**
- Caller can handle specific errors
- Better than generic "something failed"
- Exit codes map to error codes

##  Lessons Learned

### What Changed from Original Code

1. **Removed UI from Core**
   - Old: ProgressBar in crypto.cpp
   - New: Optional callback in EncryptParams

2. **Explicit Modes**
   - Old: `bool headerless`
   - New: `EncryptionMode` enum

3. **Unified Key Derivation**
   - Old: Separate functions with duplicated logic
   - New: Single `derive_key()` dispatcher

4. **Better Testability**
   - Old: Hard to test without terminal
   - New: Core library has no I/O dependencies

5. **Library Usage**
   - Old: Only CLI usable
   - New: Clean API for integration

##  Future Extensions

Architecture supports:

1. **New Modes**
   - Add to `EncryptionMode` enum
   - Implement in `keygen.cpp`
   - No changes to `crypto.cpp`

2. **GUI Wrapper**
   - Link to `libminicrypto_core`
   - Provide progress callbacks
   - No recompilation needed

3. **Server Integration**
   - Use as library
   - Async callbacks
   - No terminal assumptions

4. **Hardware Keys**
   - New mode: `EncryptionMode::HARDWARE_KEY`
   - Derive key from PKCS#11
   - Minimal changes

## [PASS] Validation

### Design Goals Achieved

- [PASS] Core library has zero UI dependencies
- [PASS] Can build as static or dynamic
- [PASS] Four distinct encryption modes
- [PASS] Clean API for library usage
- [PASS] No network dependencies
- [PASS] No time dependencies
- [PASS] Fully testable without I/O
- [PASS] Air-gapped ready

### Non-Goals (Explicitly Rejected)

- [FAIL] Network protocols (SSH, TLS)
- [FAIL] Key management servers
- [FAIL] Telemetry or analytics
- [FAIL] Auto-updates
- [FAIL] Cloud integration
- [FAIL] "Smart" features requiring network

---

**Keep it simple. Keep it offline. Keep it auditable.**