# MiniCrypto FAQ (Frequently Asked Questions)

## General Questions

### What is MiniCrypto?
MiniCrypto is a paranoid-grade, minimalist file and directory encryption utility and C++ library designed specifically for air-gapped systems and privacy-critical environments.

### What algorithms are used?
- **Cipher**: XChaCha20-Poly1305 with 192-bit extended nonce and 128-bit Poly1305 authentication tag.
- **Key Derivation Function (KDF)**: Argon2id with configurable time cost, memory, and parallelism (default: 3 iterations, 128 MB RAM, 2 threads).
- **Key-Only Mode KDF**: HKDF / BLAKE2b (keyed hash).

### Does MiniCrypto make any network calls?
**Never.** MiniCrypto contains zero networking code, zero telemetry, zero analytics, and zero external network library dependencies. It is safe for air-gapped environments.

---

## Directory Support

### Can MiniCrypto encrypt directories?
Yes! MiniCrypto can encrypt entire directory hierarchies:
```bash
# Encrypt directory
minicrypto lock my_folder/

# Decrypt directory
minicrypto unlock my_folder.mcc --output restored_folder/
```
Directories are packed into a streaming archive (`MCDA v1`), then authenticated and encrypted using XChaCha20-Poly1305.

### Is path traversal prevented during directory unpacking?
Yes. MiniCrypto strictly verifies relative paths during unpacking. Any archive containing `..`, absolute paths, or invalid characters will be immediately rejected with an error.

---

## Encryption Modes

### What is STANDARD mode?
The default mode. Your password is run through Argon2id with a unique 32-byte cryptographic salt generated via CSPRNG. Every encryption produces a completely different ciphertext.

### What is SPLIT-KEY mode?
A two-factor encryption mode requiring both a password and a physical keyfile (e.g. stored on a USB drive). Both factors are cryptographically combined in Argon2id. Without both, decryption is impossible.

### What is KEY-ONLY mode?
Designed for automated server pipelines and headless backup scripts. It uses a keyfile directly without prompting for an interactive password.

### What is HEADERLESS mode?
Headerless mode strips all plaintext metadata (format version, magic bytes, plaintext size). Only a 32-byte salt remains. The stream nonce is derived deterministically from the password and salt. This mode is steganography-friendly and useful for deniable encryption.

### What is DETERMINISTIC mode and why is it dangerous?
Deterministic mode (`--deterministic`) derives the cryptographic salt and stream nonce deterministically from the file's hash and your password.
**Risks:**
- Identical files encrypted with the same password produce identical ciphertext.
- Attackers can detect duplicate files across backups and conduct known-plaintext equality tests.
- IND-CPA security is forfeited.
Use this mode **only** if required for content-addressed deduplication systems. MiniCrypto requires explicit confirmation (`I UNDERSTAND THE RISKS`) before proceeding.

---

## Safety & Recovery

### What happens if encryption is interrupted or power fails?
MiniCrypto uses **AtomicFile** operations: data is written to a `.tmp` file and only renamed to the final destination upon successful flush and close. Your original data is never corrupted by an interrupted operation.

### Can I recover my files if I forget my password?
**No.** There are no backdoors, escrow keys, or recovery mechanisms. If the password and/or keyfile is lost, the data cannot be decrypted.

### How does secure deletion work?
When requested (`--keep` not specified), MiniCrypto performs a 3-pass overwrite (0xFF, 0x00, CSPRNG random noise) followed by `fsync` before unlinking. Note that on SSDs with wear-leveling and Copy-on-Write (CoW) filesystems, full-disk encryption is recommended alongside shredding.
