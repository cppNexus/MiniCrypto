MiniCrypto Security and Limitations

This document describes the current implementation in the repository, not an independent certification. No specialized external audit has been performed, and none is planned by the project. The code is open: anyone can review it, report a problem, or commission their own audit. Whether to use the program is the user’s decision.

MiniCrypto is provided as is, with no promise of freedom from bugs, data loss, or vulnerabilities. No test suite proves absolute security. Below, the factual properties of the code are separated from what it does not guarantee.

What Is Used
For streaming file encryption: crypto_secretstream_xchacha20poly1305 from libsodium (XChaCha20-Poly1305, 256-bit key, 24-byte stream header, 17-byte libsodium tag per message including stream overhead; blocks up to 1 MiB).
For STANDARD mode: Argon2id(password, salt). Defaults: 3 iterations, 128 MiB memory, 2 threads. The KDF parameters are recorded in the normal full header.
For SPLIT-KEY: Argon2id over the concatenation of the password bytes and the keyfile. The components are not encoded with a separate length or delimiter; different pairs of components can produce the same concatenation.
For KEY-ONLY: BLAKE2b-256 over keyfile || salt || "MINICRYPTO::KEY_ONLY::v1". This is neither HKDF nor a password KDF; its strength depends on the unpredictability of the keyfile.
For HEADERLESS: a 32-byte random salt. New files derive the stream header from the Argon2id key and the salt; old files with a random stream header continue to be readable. When a keyfile is present, the SPLIT-KEY path is applied.
For --deterministic: a separate Argon2id pre-key with fixed parameters (5 iterations, 256 MiB, 2 threads); the salt depends on the SHA-256 of the content and the pre-key; the stream header is also deterministic. This is a separate, dangerous path.
For the experimental fixed-slot container (container-create / container-open): two equal slots, Argon2id, a BLAKE2b role key, and XChaCha20-Poly1305-IETF AEAD. An empty second slot is filled with CSPRNG bytes. The format has no external audit.
What Is Actually Authenticated

In normal STANDARD, SPLIT-KEY, KEY-ONLY, and HEADERLESS streams, secretstream authenticates the encrypted messages/chunks. Decryption requires a valid final stream tag.

Do not assume the whole normal file is authenticated: the fields of the full header are not passed as associated data. In particular, plaintext_size, reserved, kdf_version, and the unused nonce field are not protected by a tag; the declared size is not checked against the actual result. After the final tag, the current decoder also does not reject any trailing data in the file. The full header reveals the magic, the mode, the KDF parameters, and the plaintext size. HEADERLESS hides the full header, but the container length still reveals the data size.

The header of a normal v2 file sets the Argon2id parameters before decryption begins. The validator allows large memory values (up to 10 GiB), so opening an untrusted file may require excessive resources or cause a system failure. Do not open unknown containers on a machine where such a load is unacceptable.

In the fixed-slot prototype, the AEAD binds the internal context, the slot role, and the slot size. This provides an integrity check of the decrypted slot given the correct password, but it does not prove that an encrypted slot is computationally indistinguishable from random filler.

What the Program Does, and What It Does Not Guarantee
Area	Actual behavior	Not guaranteed
Password modes	Argon2id is used for STANDARD, SPLIT-KEY, and password-based HEADERLESS	Protection of a weak password against brute force; reasonableness of non-default KDF parameters; inability to decrypt if the device is compromised
KEY-ONLY	BLAKE2b-256 derives the key from the keyfile, salt, and context	Protection of a low-entropy/short keyfile against offline guessing
AEAD/secretstream	Tags detect modifications of authenticated ciphertext chunks/slots	Integrity of all normal header fields; absence of defects in the implementation or libraries
HEADERLESS	Does not write the full MiniCrypto header	Hiding length, steganography, or plausible deniability
Fixed-slot container	Has two slots of identical size and tries to open both through the same API	Cryptographic indistinguishability of filler/hidden slot, constant time, protection against multiple snapshots, live observation, or disclosure of both passwords
SecureBuffer/SecureString	Request memory locking and wipe the managed buffer on destruction	Successful mlock/VirtualLock on every OS, absence of copies in all components, protection against swap/core dump/malware
AtomicFile	Writes via a temporary file and then renames	Safe exclusivity of the temporary name, fsync durability, or preservation of the existing destination in all error scenarios; if replacement fails, the current implementation may delete the previous destination
Fixed-slot private output	Uses an exclusive temporary file with restricted permissions in the supported platform path	Identical ACL/publication behavior on all OSes without separate verification
Secure delete	Performs three write passes and tries to sync/delete the file	Physical erasure on SSDs, CoW, snapshots, journals, backups; success of every write/fsync
Directories	Packs the tree into MCDA and then encrypts; unpack checks basic traversal patterns	Fully atomic unpacking, rollback of already written files, or exhaustive protection against all path attacks
Build and tests	CI and tests verify selected configurations and scenarios	Absence of bugs, support for every system/CPU, cryptographic proof, or quality of configurations that were not run
Deterministic Mode

Identical plaintext yields identical ciphertext only if the password, mode, keyfile (if used), and KDF parameters all match. This reveals file equality, links between copies, and possible repetition frequency; known or guessable plaintext candidates can be checked by comparing the result. A ciphertext match by itself does not reveal access history.

The mode does not implement searchable encryption, and a hash match does not replace the signature/authentication of a release manifest. Do not use it where leaking equality is undesirable.

Experimental Fixed-Slot Container

The container-create and container-open commands implement a prototype, not a verified deniability guarantee. Each slot has a fixed chosen size (CLI: 1–64 MiB, default 16 MiB per slot); the usable capacity is smaller than the slot size by the salt, nonce, tag, and the internal length field. The Argon2id parameters are not serialized: the file must be opened with the same parameters used at creation; the CLI uses the default values.

The mode does not protect against multiple snapshots, observation of the process/terminal, shell/process/file metadata, or coercion to disclose all passwords. Do not store important data only in this experimental format, and test it on copies first.

An external audit is not a condition of the project and is not planned. Anyone who wishes may conduct their own review and send in the results/fixes.

Practical Recommendations
Use random, unique passwords with sufficient entropy, and keep a backup of the password/keyfile separately. Do not rely on the “20 characters” rule without considering how those characters are chosen.
KEY-ONLY requires a keyfile with sufficient random entropy.
Do not delete the source files until you have verified recovery from an independent copy.
Keep several backups of important source files; encryption does not replace backups.
Treat a checksum as a check against a manifest, not as proof of authorship. A release signature only makes sense if the specific release contains a signature and the trusted public key was obtained through an independent channel.
Support and Feedback

External audit or public review is welcome but not promised. When reporting a vulnerability, include the version, platform, a minimal example, and the expected/actual behavior; do not publish real secrets or user data.