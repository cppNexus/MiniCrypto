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

<div align="center" style="background-color:#8B0000; color:#FFFFFF; padding:20px; border-radius:8px;">
  
## ⚠️ DISCLAIMER — READ BEFORE USE

**MINICRYPTO IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.**

**BY USING MINICRYPTO, YOU ACCEPT THE FOLLOWING RISKS AND RESPONSIBILITIES.**

- **LOST PASSWORDS AND KEYS:** If you lose or forget your password, keyfile, or any required encryption credentials, your encrypted data may become permanently unrecoverable. There is no password reset, backdoor, or guaranteed recovery mechanism. The developer cannot recover your data for you.

- **DATA LOSS AND CORRUPTION:** Encryption, decryption, archiving, extraction, storage failures, hardware faults, power loss, software defects, or user error may result in damaged, incomplete, or permanently lost data.

- **BACKUPS ARE YOUR RESPONSIBILITY:** Always maintain verified, independent backups of important data before encrypting, decrypting, overwriting, securely deleting, or otherwise modifying files. Never treat an encrypted copy as your only backup.

- **VERIFY BEFORE DELETING ORIGINALS:** Do not delete original files until you have independently verified the encrypted archive and confirmed that you can successfully decrypt and restore the data.

- **NO GUARANTEE OF SECURITY OR FITNESS:** Although MiniCrypto is designed to use established cryptographic primitives, no software can be guaranteed free of vulnerabilities, implementation defects, or security weaknesses. Use of this software does not guarantee confidentiality, integrity, or protection against every attack.

- **DETERMINISTIC MODE:** Deterministic encryption can reveal when identical inputs produce identical ciphertexts and may expose information about repeated data. Use it only when you understand and accept these risks.

- **SECURE DELETION LIMITATIONS:** Secure deletion cannot be guaranteed on SSDs, flash storage, copy-on-write filesystems, journaled filesystems, cloud-synced folders, or storage devices that retain historical copies or remapped blocks.

- **NO LIABILITY:** To the maximum extent permitted by applicable law, the developer and contributors shall not be liable for data loss, data corruption, loss of access, security incidents, financial loss, or any direct, indirect, incidental, special, or consequential damages arising from the use or inability to use MiniCrypto.

**YOU ARE SOLELY RESPONSIBLE FOR YOUR PASSWORDS, KEYS, BACKUPS, AND THE CONSEQUENCES OF USING THIS SOFTWARE.**

**IF YOU DO NOT UNDERSTAND THESE RISKS, DO NOT USE MINICRYPTO ON IMPORTANT DATA.**

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
