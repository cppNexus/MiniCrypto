# Security Documentation

##  Cryptographic Design

### Encryption Algorithm
- **Cipher**: XChaCha20-Poly1305 (via libsodium secretstream)
- **Key Size**: 256 bits
- **Nonce Size**: 192 bits (XChaCha20 extended nonce)
- **Tag Size**: 128 bits (Poly1305 MAC)
- **Chunk Size**: 1 MB (streaming encryption)

### Key Derivation
- **Algorithm**: Argon2id
- **Default Parameters**:
  - Time cost: 3 iterations
  - Memory cost: 128 MB
  - Parallelism: 2 threads
- **Purpose**: Password → 256-bit encryption key

### Domain Separation
All derived values use domain-specific contexts to prevent cross-protocol attacks:

```cpp
"MINICRYPTO::KEY_ONLY::v1"           // Key-only mode
"MINICRYPTO::HEADERLESS_NONCE::v1"   // Headerless nonce derivation
"MINICRYPTO::DETERMINISTIC_PREKEY::v1"  // Deterministic pre-key
"MINICRYPTO::DETERMINISTIC_SALT::v1"    // Deterministic salt
```

##  Encryption Modes

### 1. STANDARD (Recommended)
```bash
minicrypto lock file.txt
```

**Security Properties:**
- [PASS] IND-CPA secure
- [PASS] Random salt per encryption
- [PASS] Authenticated encryption
- [PASS] No equality leakage

**Use Cases:**
- Personal file encryption
- General-purpose security

### 2. SPLIT-KEY
```bash
minicrypto lock file.txt --mode split-key --keyfile usb.key
```

**Security Properties:**
- [PASS] Two-factor security (password + keyfile)
- [PASS] IND-CPA secure
- [PASS] Both factors required to decrypt

**Use Cases:**
- High-value data
- Physical + knowledge authentication

### 3. KEY-ONLY
```bash
minicrypto lock file.txt --mode key-only --keyfile master.key
```

**Security Properties:**
- [PASS] No password prompt (automated systems)
- [PASS] Uses HKDF instead of Argon2 (no password = no brute-force risk)
- [PASS] IND-CPA secure

**Use Cases:**
- Automated backups
- Server-side encryption
- Non-interactive systems

### 4. HEADERLESS
```bash
minicrypto lock file.txt --mode headerless
```

**Security Properties:**
- [PASS] Minimal header (16-byte salt only)
- [PASS] Deterministic nonce (derived from password+salt)
- [PASS] Steganography-friendly
- [PASS] Plausible deniability

**Use Cases:**
- Steganography
- Hiding encrypted data
- Deniable encryption

**Trade-offs:**
- [WARNING] Must remember encryption parameters
- [WARNING] No metadata about original file size

## [WARNING] DETERMINISTIC MODE (DANGEROUS)

### Overview
```bash
minicrypto lock file.txt --deterministic
```

**What it does:**
- Same file + same password = **identical ciphertext**
- Salt is derived from: `BLAKE2b(SHA256(file) || pre-key)`
- Pre-key is derived from: `Argon2id(password, fixed_salt)`

**CRITICAL: YOU LOSE IND-CPA SECURITY**

### Security Analysis

#### What You Gain
- Deduplication possible
- Hash-based file lookup
- Integrity checking without decryption

#### What You LOSE

1. **Equality Testing**
```
Attacker: "Are these two encrypted files the same?"
→ Compare hashes
→ If identical: same plaintext + same password
```

2. **Known-Plaintext Enhancement**
```
Attacker: "I suspect file.mcc is either doc1.txt or doc2.txt"
→ Encrypt both with dictionary passwords
→ Compare hashes
→ Find password + identify plaintext
```

3. **Frequency Analysis**
```
Backup system with 10,000 files:
→ hash(file1.mcc) appears 50 times
→ "This file was encrypted 50 times = accessed 50 times"
→ Metadata leakage
```

4. **IND-CPA Violation**
```
IND-CPA: Attacker can't distinguish which of two plaintexts was encrypted
Deterministic: encrypt(m1) ≠ encrypt(m2) → trivially distinguishable
```

### Safe Usage Conditions

Use deterministic mode **ONLY IF**:
- [PASS] Plaintexts have high entropy (not from dictionary)
- [PASS] Passwords are strong and unique
- [PASS] No chosen-plaintext attack risk
- [PASS] Deduplication benefit > IND-CPA loss
- [PASS] You fully understand the risks

### Implementation Details

#### Why NOT Direct Password?
```cpp
// [FAIL] WRONG (vulnerable to oracle attacks)
salt = BLAKE2b(file_hash || password)

// [PASS] CORRECT (pre-key adds cost)
pre_key = Argon2id(password, fixed_salt)  // Expensive!
salt = BLAKE2b(file_hash || pre_key)
```

**Benefit**: Attacker must run Argon2id for each password guess, even if they have the file hash.

#### Pre-Key Parameters
```cpp
Time: 5 iterations (higher than default)
Memory: 256 MB (higher than default)
Threads: 2
```

**Why higher**: This is a one-time cost per encryption, but protects against brute-force.

### User Confirmation

Deterministic mode requires explicit user confirmation:

```
[WARNING]  WARNING: DETERMINISTIC ENCRYPTION MODE

This mode produces IDENTICAL ciphertext for identical plaintext + password.

SECURITY IMPLICATIONS:
  • You LOSE IND-CPA security
  • Attackers CAN detect duplicate files
  • Attackers CAN perform equality testing
  • Known-plaintext attacks are EASIER

USE ONLY IF:
  • You need backup deduplication
  • You need searchable encryption
  • You FULLY UNDERSTAND the risks

Type 'I UNDERSTAND THE RISKS' to proceed:
```

##  Memory Security

### mlock() Protection
- All keys and passwords are locked in memory (`mlock()`)
- Prevents swapping to disk
- Requires `CAP_IPC_LOCK` capability

```bash
# Grant capability to binary
sudo setcap cap_ipc_lock=ep minicrypto
```

### Secure Zeroization
- All sensitive buffers zeroed with `sodium_memzero()`
- Compiler cannot optimize away
- RAII wrappers ensure cleanup

```cpp
SecureBuffer key(32);  // mlock'd
derive_key(..., key.data(), ...);
// Use key
// ~SecureBuffer() → sodium_memzero + munlock
```

### No Copies
- Passwords use `SecureString` (not `std::string`)
- No copies in memory
- Immediate zeroization on destruction

##  File Operations

### Atomic Writes
```cpp
AtomicFile output(path);
output.get() << data;  // Write to .tmp
output.commit();       // Atomic rename
```

**Benefits:**
- Never corrupt original on failure
- Disk-full safety
- Clean error recovery

### Secure Deletion
```
3-pass overwrite:
  Pass 1: 0xFF (all ones)
  Pass 2: 0x00 (all zeros)
  Pass 3: random data
fsync() after each pass
unlink()
```

**Limitations (documented):**
- [WARNING] SSDs: wear-leveling may keep copies
- [WARNING] CoW filesystems: snapshots persist
- [WARNING] Journaling: metadata logged

**Recommendation**: Encrypt entire disk + use TRIM

##  Threat Model

### What We Protect Against

[PASS] **Passive Attacker**
- Cannot decrypt without password
- Cannot tamper without detection (MAC)
- Cannot distinguish ciphertexts (except deterministic mode)

[PASS] **Active Attacker**
- Tampering detected by Poly1305 MAC
- Wrong password → decryption fails
- Bit-flips caught immediately

[PASS] **Offline Dictionary Attack**
- Expensive Argon2id makes brute-force slow
- Configurable time/memory parameters
- No shortcuts available

### What We DON'T Protect Against

[FAIL] **Compromised System**
- Malware can capture password at entry
- Keyloggers can steal credentials
- Memory dumps can extract keys

[FAIL] **Side-Channel Attacks**
- Timing attacks: use constant-time primitives (libsodium)
- Power analysis: hardware-dependent
- Cache attacks: OS-dependent

[FAIL] **Rubber-Hose Cryptanalysis**
- Physical threats to user
- Legal compulsion
- No protection possible

[FAIL] **Quantum Computers**
- XChaCha20: Grover's algorithm → 128-bit security (acceptable)
- Argon2id: quantum-resistant (memory-hard)
- Poly1305: quantum-vulnerable (but still requires key)

##  Security Comparison

| Feature | STANDARD | SPLIT-KEY | KEY-ONLY | HEADERLESS | DETERMINISTIC |
|---------|----------|-----------|----------|------------|---------------|
| **IND-CPA** | [PASS] | [PASS] | [PASS] | [PASS] | [FAIL] |
| **Authenticated** | [PASS] | [PASS] | [PASS] | [PASS] | [PASS] |
| **Two-factor** | [FAIL] | [PASS] | [FAIL] | [FAIL] | [FAIL] |
| **No password** | [FAIL] | [FAIL] | [PASS] | [FAIL] | [FAIL] |
| **Stealth** | [FAIL] | [FAIL] | [FAIL] | [PASS] | [FAIL] |
| **Deduplication** | [FAIL] | [FAIL] | [FAIL] | [FAIL] | [PASS] |
| **Equality leak** | [FAIL] | [FAIL] | [FAIL] | [FAIL] | [PASS] [WARNING] |

##  Audit & Verification

### Code Review
- Small codebase (~2000 LOC)
- No custom crypto (uses libsodium)
- Clear separation of concerns
- Well-documented assumptions

### Dependencies
- **libsodium**: Audited, widely used
- **libargon2**: Reference implementation
- No other crypto libraries

### Build Verification
```bash
# Verify no network code
nm minicrypto | grep -i socket
# (should be empty)

# Verify no unexpected syscalls
strace -e trace=network minicrypto lock test.txt
# (should show no network calls)

# Verify static linking (air-gapped)
ldd minicrypto-static
# (should say "not a dynamic executable")
```

##  Best Practices

### Password Selection
- [PASS] Use 20+ characters
- [PASS] Mix uppercase, lowercase, numbers, symbols
- [PASS] Use password manager
- [FAIL] Don't reuse passwords
- [FAIL] Don't use dictionary words

### Keyfile Management
- [PASS] Store on separate device (USB)
- [PASS] Keep backup in secure location
- [PASS] Use hardware key if possible
- [FAIL] Don't store with encrypted files
- [FAIL] Don't send over network

### Parameter Selection
```bash
# Fast (mobile/embedded)
--argon-mem 64 --argon-time 2

# Balanced (default)
--argon-mem 128 --argon-time 3

# Paranoid (servers)
--argon-mem 512 --argon-time 8
```

### Mode Selection Decision Tree
```
Need automated encryption (no password prompt)?
  → KEY-ONLY mode

Need two-factor security?
  → SPLIT-KEY mode

Need steganography/deniability?
  → HEADERLESS mode

Need deduplication? (and understand risks?)
  → STANDARD + --deterministic (DANGEROUS!)

Otherwise:
  → STANDARD mode (secure default)
```

##  Incident Response

### Suspected Compromise
1. Change password immediately
2. Re-encrypt all files with new password
3. Securely delete old encrypted files
4. Consider key rotation

### Lost Password
- No recovery possible (by design)
- Keep encrypted backup of recovery info
- Consider split-key mode with backup keyfile

### Lost Keyfile
- If SPLIT-KEY: password alone won't work
- Keep encrypted backup of keyfile
- Store backup in different location

##  References

- [libsodium documentation](https://doc.libsodium.org/)
- [Argon2 specification](https://github.com/P-H-C/phc-winner-argon2)
- [XChaCha20-Poly1305 IETF draft](https://tools.ietf.org/html/draft-arciszewski-xchacha-03)
- [Deterministic Encryption Considered Harmful](https://eprint.iacr.org/2019/1272)

---

**Last Updated**: 2025-12-14  
**Version**: 2.1  
**Status**: Production Ready