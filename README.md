# MiniCrypto v1.1

[![Cross-Platform CI](https://github.com/cppNexus/MiniCrypto/actions/workflows/ci.yml/badge.svg)](https://github.com/cppNexus/MiniCrypto/actions/workflows/ci.yml)

**Minimalist file and directory encryption for offline / air-gapped systems**

> This README describes the current implementation, not an independent certification.
> No external security audit has been performed or is planned. See
> [docs/SECURITY.md](docs/SECURITY.md) for the exact properties and limitations.

## Design Philosophy

- **No network code** — the current sources contain no networking, telemetry, or auto-update
- **Library-first** — core crypto and directory archiving have no UI dependencies
- **Mode flexibility** — from password-only to keyfile-only and split-key
- **Directory support** — directories are packed into an archive (MCDA) and encrypted as a file
- **Headerless mode** — omits the full MiniCrypto header (no steganography or deniability guarantee)
- **Air-gap friendly** — optional static CLI build (completeness depends on your toolchain)

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

# Check that an encrypted file decrypts and its stream tags are valid
minicrypto verify secret.txt.mcc

# Encrypt an entire directory
minicrypto lock my_project/
# -> my_project.mcc
# The default archive is next to the source directory; use --output to relocate it.

# Decrypt a directory archive
minicrypto unlock my_project.mcc
# -> my_project.restored/ (directory tree restored)

# Password + keyfile
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

- Password → Argon2id (random 32-byte salt) → key
- Defaults: 3 iterations, 128 MiB memory, 2 threads
- Normal v2 file: an open header (mode, KDF parameters, plaintext size) followed by the encrypted stream
- The header fields are **not** authenticated as AEAD associated data; only the encrypted chunks are

`verify` decrypts the stream into a temporary file to check the secretstream tags, then
attempts to securely delete that temporary file (best-effort). It does not prove the file
matches the original, and it does not authenticate the whole header.

### 2. SPLIT-KEY

```bash
minicrypto lock secret.txt --mode split-key --keyfile usb.key
```

- Password bytes ‖ keyfile bytes → Argon2id → key
- Both components are required to decrypt
- The components are concatenated without a length prefix or delimiter, so this does not
  guarantee two independent factors
- A weak password or a keyfile the attacker can obtain is not compensated for

### 3. KEY-ONLY

```bash
minicrypto lock secret.txt --mode key-only --keyfile master.key
```

- BLAKE2b-256 over `keyfile ‖ salt ‖ "MINICRYPTO::KEY_ONLY::v1"` → key
- **Not HKDF and not a password KDF**
- No password required
- Security depends entirely on the keyfile being random and unpredictable;
  a short or low-entropy keyfile can be guessed offline

### 4. HEADERLESS

```bash
minicrypto lock secret.txt --mode headerless
```

- No full MiniCrypto header: 32-byte salt, stream header, ciphertext
- Key via the STANDARD path (password only) or the SPLIT-KEY path (when a keyfile is given)
- New files derive the stream header from the Argon2id key and the salt; older files with
  a random stream header remain readable
- **Not steganography and not plausible deniability.** File length still reveals the data size

### 5. DETERMINISTIC (⚠️ dangerous mode)

```bash
minicrypto lock backup.tar --deterministic
```

- Same plaintext, password, mode, keyfile (if used), and KDF parameters produce the same ciphertext
- This reveals equality of files and links between copies; guessable plaintext candidates
  can be tested by comparing ciphertexts
- Requires explicit interactive confirmation (`I UNDERSTAND THE RISKS`)
- Intended for cases such as backup deduplication where that leakage is acceptable
- See [DETERMINISTIC_WARN.txt](DETERMINISTIC_WARN.txt)

### Experimental: fixed-slot container

```bash
minicrypto container-create ...
minicrypto container-open ...
```

A prototype with two equal-size slots (Argon2id, BLAKE2b role key, XChaCha20-Poly1305-IETF AEAD).
It is **not** a verified deniability guarantee, has no external audit, and does not protect against
multiple snapshots, observation of the process, or coercion. Do not keep the only copy of
important data in this format. See [docs/SECURITY.md](docs/SECURITY.md) for details and
command options.

## Architecture

```
minicrypto/
├── core/                     # Crypto library (no UI dependencies; performs file I/O)
│   ├── crypto.cpp/h          # Streaming encryption/decryption/verification
│   ├── deniable.cpp/h        # Experimental fixed-slot container
│   ├── dir_ops.cpp/h         # Directory archive (MCDA) & encryption
│   ├── keygen.cpp/h          # Key derivation (Argon2id, BLAKE2b)
│   ├── format.cpp/h          # v2 header & validation
│   ├── secure_memory.cpp/h   # SecureBuffer/SecureString, best-effort memory locking
│   └── file_ops.cpp/h        # AtomicFile, best-effort secure_delete
│
├── ui_cli/                   # CLI frontend
│   ├── main.cpp              # Argument parsing & command dispatch
│   └── ui.cpp/h              # Progress bar, password prompt
│
├── tests/
│   └── test_main.cpp         # Unit & integration tests
│
├── docs/
│   ├── ARCHITECTURE.md       # Implementation overview
│   ├── SECURITY.md           # Facts, limitations, non-guarantees
│   └── DENIABLE_STORAGE_DESIGN_PLAN.md  # Fixed-slot prototype plan
│
├── .github/workflows/        # CI, release builds, static/dependency checks
│
├── FAQ.md
├── DETERMINISTIC_WARN.txt
├── PROJECT_STRUCTURE.md
├── CMakeLists.txt
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

Passing tests only means the covered scenarios passed in that build.

### Static CLI Build

```bash
mkdir build && cd build
cmake .. -DBUILD_STATIC_CLI=ON
make
```

This requests static linking. How complete it is depends on your toolchain and libraries;
check the resulting binary on your platform (for example with `ldd`).

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
params.argon_mem_kb = 128 * 1024;  // 128 MiB
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

// Archives the directory and encrypts the archive
encrypt_directory("my_folder", "my_folder.mcc", password, params);

// Decrypt back to a folder
DecryptParams dec_params;
decrypt_directory("my_folder.mcc", "restored_folder", password, dec_params);
```

Directory unpacking writes files sequentially; it is not a transaction, and files written
before an error may remain on disk.

## Security Features and Limits

- **Encryption**: libsodium `crypto_secretstream_xchacha20poly1305` (XChaCha20-Poly1305), chunks up to 1 MiB
- **KDF**: Argon2id for STANDARD, SPLIT-KEY, and password-based HEADERLESS (configurable t/m/p); plain BLAKE2b-256 for KEY-ONLY
- **Authentication**: a Poly1305 tag on every encrypted chunk. The v2 header fields are not covered, `plaintext_size` is not compared with the actual result, and trailing bytes after the final tag are not rejected
- **Untrusted files**: the header sets Argon2id parameters before decryption (memory up to 10 GiB is accepted), so opening an untrusted file can consume excessive resources
- **Memory**: `SecureBuffer`/`SecureString` wipe their own buffers and request memory locking; locking can fail, and copies outside these classes are not protected
- **Secure deletion**: best-effort 3-pass overwrite (0xFF, 0x00, random) with fsync, then unlink. Not reliable on SSDs, CoW filesystems, or with snapshots/backups
- **File writes**: `AtomicFile` writes a `.tmp` file and renames it. If the rename onto an existing destination fails, the implementation removes the old destination and retries, so the old file is not guaranteed to survive a failure
- **Path traversal**: directory unpack rejects paths containing `..` and leading `/` or `\`. This is a basic check, not a full sandbox guarantee on every OS

## Testing

```bash
# Run built-in self-tests via CLI
minicrypto test

# Run the full automated test suite (unit + integration)
./build/minicrypto_tests
```

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
A checksum only checks a file against a manifest; it is not proof of authorship.

## Further Reading

- [docs/SECURITY.md](docs/SECURITY.md) — what is and is not guaranteed
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — implementation overview
- [FAQ.md](FAQ.md)
- [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md)

## License

MIT License — see [LICENSE](LICENSE) file.