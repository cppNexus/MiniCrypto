MiniCrypto: Project Architecture

This document describes the current implementation, does not promise that it is free of errors, and does not replace reviewing the source code. No specialized external audit has been performed; whether to commission one is up to interested users.

Components
core/crypto.cpp, core/crypto.h: streaming file encryption, decryption, and verification.
core/keygen.cpp, core/keygen.h: key derivation for the modes.
core/format.cpp, core/format.h: the MiniCrypto v2 full header and its validation.
core/deniable.cpp, core/deniable.h: the experimental fixed-slot container, separate from the legacy formats.
core/dir_ops.cpp, core/dir_ops.h: packing and unpacking of an MCDA directory.
core/secure_memory.cpp, core/secure_memory.h: buffers, wiping, and the attempt to lock memory.
core/file_ops.cpp, core/file_ops.h: temporary files, atomic publication in some operations, best-effort secure delete.
ui_cli/: CLI, passwords, warnings, and progress. Core does not depend on the CLI/UI, but performs file I/O itself.
tests/test_main.cpp: unit and integration tests of selected scenarios; a finite number of tests does not prove the absence of defects.
Algorithms by Mode
Mode	Key material	Salt/stream header	Note
STANDARD	Argon2id over the password	Random 32-byte salt; random secretstream header	The full plaintext header contains the mode, KDF parameters, and plaintext size
SPLIT-KEY	Argon2id over the concatenation of password bytes and keyfile bytes	Random salt and secretstream header	The input components have no separate length prefix
KEY-ONLY	BLAKE2b-256 over the keyfile, salt, and domain context	Random salt and random secretstream header	Not HKDF; does not use a password KDF
HEADERLESS	The STANDARD path, or SPLIT-KEY when a keyfile is used	32-byte salt; new files derive the secretstream header from the KDF key and the salt	Old files with a random stream header remain readable; data length is visible
--deterministic	A special Argon2id pre-key; then the normal mode KDF	Salt and stream header are derived deterministically	Identical inputs reveal ciphertext equality; dangerous mode
Fixed-slot prototype	Argon2id + BLAKE2b role separation	Two fixed slots, XChaCha20-Poly1305-IETF AEAD	Experimental, with no proof of deniability

The --deterministic flag applies to the normal encryption modes; it overrides the usual random salt/header for that run. Ciphertexts can be compared as identical only if all KDF- and mode-related inputs match.

The detailed security description and limitations are in Security.md; the prototype plan is in docs/DENIABLE_STORAGE_DESIGN_PLAN.md.

Formats and Integrity

The normal v2 format writes the packed C++ Header directly (the current struct size is 84 bytes), followed by the secretstream header and the chunks. Headerless writes a 32-byte salt, then the stream header and the ciphertext. Secretstream tags authenticate the stream messages; the fields of the normal header are not passed as AAD. The plaintext_size field is not compared with the actual plaintext; some unknown/reserved fields do not affect derivation. After TAG_FINAL, trailing bytes are currently not rejected.

Normal files use AtomicFile, but its temporary name and replacement path have limitations; this is not a promise that the old destination survives any failure. The new fixed-slot module uses a separate private temp path and publishes the output only after the slot has been verified. Directory unpacking consists of sequential file writes and is not a transaction over the whole tree.

The MCDA archive stores the directory structure inside the encrypted file stream when directory lock/unlock is used. The unpacking checks block the main traversal forms, but they are not a full sandbox guarantee on every OS.

Memory and Deletion

SecureBuffer/SecureString wipe their own managed buffers and try to use OS memory locking. Locking may fail; temporary std::vectors, library buffers, the keyfile, and copies outside these classes do not automatically become protected. This is not protection against malware, core dumps, or observation of input.

secure_delete performs several write passes and tries to sync the changes before unlink. Errors and storage-medium properties limit the result; physical erasure on SSDs, CoW, snapshots, and backup systems is not guaranteed.

Build and Tests

CMake builds the core library, the CLI, and the test executable when the BUILD_TESTS option is enabled. By default BUILD_SHARED_LIBS=OFF; BUILD_STATIC_CLI requests static linking, but how complete the resulting static linking is depends on the toolchain and libraries. Check the actual build for your platform.

CI and CTest run specific configurations. A passing test means that the checked scenarios passed in that build; it does not prove cryptographic security, support for all systems, or the absence of errors.

Limits of the Promises

MiniCrypto uses libsodium and Argon2, but choosing well-known libraries does not prove the correctness of the whole scheme or the integration. The project promises only the described behavior of the implementation in a specific build. The program is provided “as is”; backups and the decision to use it remain the user’s responsibility. It is impossible to promise absolute undecryptability: the correct credentials are meant to decrypt, and an attacker can guess weak credentials or compromise the device.