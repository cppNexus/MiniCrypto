# MiniCrypto v1

[![Cross-Platform CI](https://github.com/cppNexus/MiniCrypto/actions/workflows/ci.yml/badge.svg)](https://github.com/cppNexus/MiniCrypto/actions/workflows/ci.yml)

**Minimalist, paranoid-grade file and directory encryption for air-gapped systems**

## Design Philosophy

- **Zero network dependencies** — works completely offline
- **Zero telemetry** — no metrics, no phone home
- **Library-first** — core crypto and directory archiving have no UI dependencies
- **Mode flexibility** — from password-only to keyfile-only and split-key
- **Directory support** — seamless streaming archive packing/unpacking and encryption
- **Headerless support** — for steganography and plausible deniability
- **Air-gap ready** — static builds, deterministic builds, no runtime surprises

## ⚠️ CRITICAL WARNING — READ BEFORE USE

**MINICRYPTO CAN CAUSE PERMANENT AND IRREVERSIBLE DATA LOSS.**

By using this software, you acknowledge and accept the following risks:

- **LOST PASSWORDS OR KEYFILES:** If you lose or forget a required password or keyfile, your encrypted data may become permanently unrecoverable. There is no password reset, master key, backdoor, or guaranteed recovery mechanism. The developer cannot recover your data.
- **CORRUPTED OR LOST DATA:** Software defects, incorrect usage, hardware failures, power loss, filesystem errors, interrupted operations, or other unforeseen circumstances may damage or permanently destroy your data.
- **BACKUPS ARE YOUR RESPONSIBILITY:** Always maintain independent backups of important files before encrypting, decrypting, archiving, extracting, or deleting data.
- **VERIFY BEFORE DELETING ORIGINALS:** Never delete original files until you have verified the encrypted output and successfully decrypted and restored a test copy.
- **NO GUARANTEE OF SECURITY:** No software is guaranteed to be free of vulnerabilities, implementation errors, or security weaknesses. Use this software only if you understand and accept the associated risks.
- **SECURE DELETION IS NOT GUARANTEED:** SSDs, flash storage, copy-on-write filesystems, journaling, wear leveling, snapshots, and backups may prevent reliable physical erasure of data.
- **DETERMINISTIC ENCRYPTION:** Deterministic mode may reveal relationships between repeated plaintext inputs and their ciphertexts. Use it only if you understand the implications.
- **NO LIABILITY:** MiniCrypto is provided under the terms of the MIT License, including its warranty disclaimer and limitation of liability. To the maximum extent permitted by applicable law, the authors and contributors disclaim liability for data loss, corruption, loss of access, security incidents, or other damages arising from the use of this software.

**YOU ARE SOLELY RESPONSIBLE FOR SAFEGUARDING YOUR PASSWORDS, KEYFILES, AND BACKUPS.**

**IF YOU CANNOT AFFORD TO LOSE THE DATA, DO NOT USE MINICRYPTO WITHOUT VERIFIED, INDEPENDENT BACKUPS.**

## Quick Start

```bash
# Encrypt a file
minicrypto lock secret.txt
# -> secret.txt.mcc

# Decrypt a file
minicrypto unlock secret.txt.mcc
# -> secret.txt

# Verify an encrypted backup without restoring it
minicrypto verify secret.txt.mcc

# Encrypt an entire directory
minicrypto lock my_project/
# -> my_project.mcc
# The default archive is next to the source directory; use --output to relocate it.

# Decrypt a directory archive
minicrypto unlock my_project.mcc
# -> my_project.restored/ (full directory tree restored)

# Two-factor: password + keyfile
minicrypto lock secret.txt --mode split-key --keyfile usb.key
minicrypto unlock secret.txt.mcc --mode split-key --keyfile usb.key
```

## Encryption Modes

### 1. STANDARD (Default)

```bash
# Encrypt a file
minicrypto lock secret.txt

# Encrypt an entire directory
minicrypto lock ~/Documents/project

# Decrypt a directory archive (defaults to project.restored/)
minicrypto unlock project.mcc

# Or choose the destination explicitly
minicrypto unlock project.mcc --output ./project/
```

- Password → Argon2id → Key
- Full header with authenticated parameters
- Best for typical use cases

`verify` authenticates the complete encrypted stream without re-encrypting it.
It temporarily decrypts to a file and securely deletes that temporary plaintext.

### 2. SPLIT-KEY

```bash
minicrypto lock secret.txt --mode split-key --keyfile usb.key
```

- Password + Keyfile → Argon2id → Key
- Both components required to decrypt
- Physical + knowledge security (Two-Factor Encryption)

### 3. KEY-ONLY

```bash
minicrypto lock secret.txt --mode key-only --keyfile master.key
```

- Keyfile → HKDF-BLAKE2b → Key
- No password required
- Pure keyfile authentication
- Perfect for automated backup pipelines

### 4. HEADERLESS

```bash
minicrypto lock secret.txt --mode headerless
```

- Minimal header (salt only, 32 bytes)
- Deterministic nonce derivation
- Steganography-friendly
- Deniable encryption

### 5. DETERMINISTIC ([WARNING] Dangerous Footgun Mode)

```bash
minicrypto lock backup.tar --deterministic
```

- Produces identical ciphertext for identical plaintext + password
- Requires explicit interactive confirmation
- Specifically for backup deduplication systems

## Architecture

```
minicrypto/
├── core/                     # Pure crypto library (no UI dependencies)
│   ├── crypto.cpp/h          # Encryption/decryption engine
│   ├── dir_ops.cpp/h         # Directory archive & recursive encryption
│   ├── keygen.cpp/h          # Key derivation (Argon2id, BLAKE2b/HKDF)
│   ├── format.cpp/h          # File format constants & header validation
│   ├── secure_memory.cpp/h   # SecureBuffer/SecureString, mlock
│   └── file_ops.cpp/h        # AtomicFile, 3-pass secure_delete
│
├── ui_cli/                   # CLI frontend
│   ├── main.cpp              # Argument parsing & command dispatch
│   └── ui.cpp/h              # ProgressBar, interactive password prompt
│
├── tests/
│   └── test_main.cpp         # 15 unit & integration tests
│
├── docs/
│   ├── ARCHITECTURE.md       # Detailed design decisions
│   └── SECURITY.md           # Threat model & security analysis
│
├── .github/workflows/
│   ├── ci.yml                # Cross-platform CI (Linux / macOS / Windows)
│   ├── release.yml           # Release builds for Debian/Rocky/Arch, macOS & Windows
│   └── security-audit.yml    # Static binary & dependency security checks
│
├── FAQ.md                    # Common questions & answers
├── DETERMINISTIC_WARN.txt    # Extended warning for deterministic mode
├── PROJECT_STRUCTURE.md      # Developer onboarding guide
├── CMakeLists.txt            # Build system (static/shared/CLI/tests)
└── LICENSE                   # MIT
```

## Build Options

### Standard Build (Dynamic)

```bash
mkdir build && cd build
cmake ..
make -j
sudo make install
```

### Run Tests

```bash
mkdir build && cd build
cmake .. -DBUILD_TESTS=ON
make -j
ctest --output-on-failure
# Or directly:
./minicrypto_tests
```

### Static Build (Air-gapped Systems)

```bash
mkdir build && cd build
cmake .. -DBUILD_STATIC_CLI=ON
make
# Result: fully static binary, no runtime dependencies
```

### Library Only (No CLI)

```bash
cmake .. -DBUILD_CLI=OFF
make
sudo make install
```

### Shared Library

```bash
cmake .. -DBUILD_SHARED_LIBS=ON
make
sudo make install
```

## Library API

Filesystem APIs accept `std::filesystem::path`. To pass UTF-8 path text portably
(including on Windows), construct paths with `std::filesystem::u8path(u8"...")`;
Windows callers may also pass paths constructed from native wide strings.

### Example: Encrypting a File

```cpp
#include <minicrypto/core/crypto.h>

using namespace minicrypto;

// Prepare parameters
EncryptParams params;
params.mode = EncryptionMode::STANDARD;
params.argon_time = 3;
params.argon_mem_kb = 128 * 1024;  // 128 MB
params.argon_threads = 2;

// Progress callback
params.progress_callback = [](uint64_t bytes) {
    std::cout << "Encrypted: " << bytes << " bytes\r" << std::flush;
};

// Encrypt
SecureString password("my_password", 11);
encrypt_file("input.txt", "output.mcc", password, params);
```

### Example: Encrypting a Directory

```cpp
#include <minicrypto/core/dir_ops.h>

using namespace minicrypto;

EncryptParams params;
SecureString password("my_password", 11);

// Recursively archives and encrypts the directory
encrypt_directory("my_folder", "my_folder.mcc", password, params);

// Decrypt back to a folder
DecryptParams dec_params;
decrypt_directory("my_folder.mcc", "restored_folder", password, dec_params);
```

## Security Features

- **Encryption**: XChaCha20-Poly1305 (libsodium secretstream)
- **KDF**: Argon2id (configurable t/m/p)
- **Authentication**: Poly1305 AEAD tag on every chunk
- **Memory**: `mlock()` to prevent swapping sensitive keys & passwords
- **Secure deletion**: 3-pass overwrite (0xFF, 0x00, CSPRNG noise) + fsync
- **Safe I/O**: Atomic writes (`.tmp` write followed by atomic `rename`)
- **Path Traversal Protection**: Directory unpack checks for `..` and absolute paths

## Testing

```bash
# Run built-in self-tests via CLI
minicrypto test

# Run full automated test suite (unit + integration)
./build/minicrypto_tests
```

## Release verification
## Release Signature Verification

Official MiniCrypto releases are signed using [minisign](https://jedisct1.github.io/minisign/).

The release signing public key is:

```text
untrusted comment: minisign public key 019A61594A625613
RWQTVmJKWWGaAR24YFh9XPQiwNlIyNf0ZeMsWuzs09avgCani/6Nzeoo
```

Save the key as `minicrypto-release.pub`.

Verify the signature of the release checksum manifest:

```bash
minisign -Vm SHA256SUMS -p minicrypto-release.pub
```

Then verify the downloaded artifacts against the checksums listed in `SHA256SUMS`.

**Security note:** Obtain and verify the public key through a trusted channel independent of the downloaded release artifacts.

## License

MIT License — see [LICENSE](LICENSE) file.
