MiniCrypto FAQ
General Information
What is MiniCrypto?

MiniCrypto is an offline utility and C++ library for encrypting files and directories. The project is open, but its openness and the existence of tests are not proof that vulnerabilities are absent. No specialized external audit has been performed or is planned; anyone who wishes may review the code themselves or commission their own audit.

The program is provided “as is”. The decision to use it is made by the user, who bears the risk of use. The project does not promise freedom from errors, absolute impossibility of decryption, or data safety in the event of any error. An authorized user with the correct key must be able to decrypt the file; the password, the keyfile, and the state of the device affect strength.

Which cryptographic algorithms are used?
Normal file modes: libsodium crypto_secretstream_xchacha20poly1305 for a stream of chunks up to 1 MiB.
STANDARD: Argon2id with a salt; defaults are 3 iterations, 128 MiB memory, 2 threads.
SPLIT-KEY: Argon2id takes the concatenation of the password bytes and the keyfile.
KEY-ONLY: plain BLAKE2b-256 over the keyfile bytes, the salt, and the context. This is neither HKDF nor a password KDF; a short or predictable keyfile can be brute-forced.
The new fixed-slot prototype: Argon2id, BLAKE2b for separating keys per slot, and libsodium XChaCha20-Poly1305-IETF AEAD.
Does the program make network requests?

In the current sources, MiniCrypto does not implement network communication, telemetry, or auto-update. This is a description of the code, not a guarantee of the behavior of a third-party build, the OS, or dependencies.

Directories
How is a directory encrypted?

The directory is packed into a MiniCrypto archive (MCDA), after which the archive is encrypted as a file. The names and contents of files are inside the encrypted stream, but the outer container reveals the length. Unpacking performs basic checks for dangerous paths; this is not a promise of complete isolation from all file-path attacks. On error, files extracted earlier may remain on disk.

Encryption Modes
STANDARD

The password is processed by Argon2id with a new random 32-byte salt. The full header openly contains the mode, the KDF parameters, and the declared file size. The header parameters are not part of the AEAD associated data; the declared size is not checked against the decrypted size.

SPLIT-KEY

The password and keyfile are needed together: their bytes are concatenated and fed into Argon2id. This does not prove the existence of two independent factors and does not compensate for a weak password or a keyfile accessible to an attacker. If either component is lost, the file may become inaccessible.

KEY-ONLY

No password is requested. The key is computed with BLAKE2b-256 from the keyfile, a random salt, and the mode context. Argon2id is not used here, so the keyfile must have sufficient random entropy. Store a backup separately from the container.

HEADERLESS

This mode does not write the full MiniCrypto header: the file contains a 32-byte salt, the secretstream header, and the ciphertext. The file length reveals the size of the original data, taking the format into account. This is not steganography and not plausible deniability. Old files with a random secretstream header remain readable.

Deterministic Mode

If the plaintext, password, mode, keyfile, and KDF parameters match, the containers become identical. This reveals equality and links between copies; access history cannot be learned from equality. The mode does not implement searchable encryption and is not recommended if such disclosure is undesirable.

Experimental Fixed-Slot Container

container-create / container-open create and open a separate container made of two slots of the same chosen length. The second slot is either encrypted or filled with random bytes. This is an experimental implementation without an independent audit; external review is not a condition of the project and is not planned. The code is open, and users can review it themselves or commission an audit.

The prototype does not protect against multiple snapshots, observation of input or of the program’s execution, file and process metadata, or coercion to disclose all passwords. Equal slot size by itself does not prove their cryptographic indistinguishability. Use is at the user’s own risk; do not keep the only copy of important data in this format.

What Do the Tags Check, and What Don’t They Check?

AEAD/secretstream tags check the integrity of authenticated ciphertext chunks/slots given the correct key. They do not authenticate all fields of the normal header. verify decrypts the stream into a temporary file, but does not prove a match with the original, does not check the whole header as AEAD, and does not guarantee physical deletion of the temporary data.

Data Loss and Deletion
Can a password or keyfile be recovered?

There is no reset or escrow mechanism. If the secret is lost, the author cannot recover it. Keep independent backups of the source data and the credentials.

Does secure_delete protect against recovery?

There is no guarantee. The function performs several write passes and tries to sync and delete the file, but it cannot guarantee physical erasure on SSDs, CoW file systems, snapshots, journals, or backups; write/sync errors are possible. Deletion of the source is confirmed by a separate question in the CLI and does not happen automatically.

Are files saved atomically?

Some operations write to a temporary file and then rename it. This reduces the risk of a partial result, but it is not a universal guarantee of the old output’s safety or of durability after a power loss. Keep independent copies.