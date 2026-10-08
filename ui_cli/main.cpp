#include "../core/crypto.h"
#include "../core/dir_ops.h"
#include "../core/format.h"
#include "../core/file_ops.h"
#include "../ui_cli/ui.h"
#include <sodium.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>

using namespace minicrypto;

// ── Usage ─────────────────────────────────────────────────────────────────────

static void show_usage() {
    std::cout << R"(
MiniCrypto v2.1 — Secure file & directory encryption

USAGE:
  minicrypto lock   <file|dir>   Encrypt file or directory
  minicrypto unlock <file>       Decrypt file (or directory archive)
  minicrypto info   <file>       Show encrypted-file metadata
  minicrypto test                Run built-in self-tests

ENCRYPTION MODES:
  --mode standard      [DEFAULT] Password only
  --mode split-key     Password + keyfile (both required)
  --mode key-only      Keyfile only (no password)
  --mode headerless    Minimal header, derived nonce

OPTIONS:
  --output <path>       Output file (or directory for unlock of dir archive)
  --keyfile <file>      Key file path
  --keep                Keep source file/directory after encryption
  --no-verify           Skip post-encryption verification
  --argon-time <n>      Argon2 iterations (default: 3)
  --argon-mem <mb>      Argon2 memory in MB (default: 128)
  --argon-threads <n>   Argon2 parallelism (default: 2)

DANGEROUS OPTIONS:
  --deterministic       [WARNING] FOOTGUN: Deterministic encryption
                        Same file + password = same ciphertext.
                        Leaks equality of plaintexts!
                        You LOSE IND-CPA security!
                        Requires explicit confirmation.

EXAMPLES:
  # Encrypt a single file
  minicrypto lock secret.txt

  # Encrypt an entire directory
  minicrypto lock ~/Documents/project

  # Decrypt a directory archive back to a folder
  minicrypto unlock project.mcc --output ./project_restored

  # Split-key mode (password + keyfile)
  minicrypto lock secret.txt --mode split-key --keyfile ~/usb.key

  # Key-only mode (no password, keyfile only)
  minicrypto lock secret.txt --mode key-only --keyfile ~/master.key

  # Headerless mode (steganography-friendly)
  minicrypto lock secret.txt --mode headerless

  # Deterministic mode (DANGEROUS — deduplication only)
  minicrypto lock backup.tar --deterministic

SECURITY:
  - XChaCha20-Poly1305 (libsodium secretstream)
  - Argon2id key derivation
  - Authenticated encryption (AEAD)
  - Memory locking (mlock) for sensitive data
  - Atomic writes (write-then-rename)
  - Secure deletion (3-pass overwrite)

)" << std::flush;
}

// ── Info ──────────────────────────────────────────────────────────────────────

static void show_info(const std::string& path) {
    try {
        FileMetadata meta = read_metadata(path);

        std::cout << "File Information:\n";

        if (meta.has_full_header) {
            std::cout << "  Format version : 2\n";
            std::cout << "  Encryption mode: ";
            switch (meta.mode) {
            case EncryptionMode::STANDARD:
                std::cout << "STANDARD (password only)\n";
                break;
            case EncryptionMode::SPLIT_KEY:
                std::cout << "SPLIT-KEY (password + keyfile)\n";
                break;
            case EncryptionMode::KEY_ONLY:
                std::cout << "KEY-ONLY (keyfile only)\n";
                break;
            case EncryptionMode::HEADERLESS:
                std::cout << "HEADERLESS (derived nonce)\n";
                break;
            }
            std::cout << "  Original size  : " << meta.plaintext_size << " bytes\n";
            std::cout << "  Encryption     : XChaCha20-Poly1305\n";
            std::cout << "  KDF            : Argon2id\n";
            std::cout << "    Time         : " << meta.argon_time     << " iterations\n";
            std::cout << "    Memory       : " << (meta.argon_mem_kb / 1024) << " MB\n";
            std::cout << "    Threads      : " << meta.argon_threads  << "\n";
        } else {
            std::cout << "  [!] Headerless file (minimal metadata)\n";
            std::cout << "  Mode           : HEADERLESS or unknown\n";
            std::cout << "  Decryption requires matching parameters\n";
        }
    } catch (const CryptoException& e) {
        std::cerr << "Error: " << e.what() << "\n";
    }
}

// ── Deterministic mode confirmation ───────────────────────────────────────────

static bool deterministic_confirmation() {
    std::cerr << "\n";
    std::cerr << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
    std::cerr << "DETERMINISTIC ENCRYPTION MODE WARNING\n";
    std::cerr << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
    std::cerr << "\n";
    std::cerr << "This mode produces IDENTICAL ciphertext for identical plaintext + password.\n";
    std::cerr << "\n";
    std::cerr << "SECURITY IMPLICATIONS:\n";
    std::cerr << "  • You LOSE IND-CPA security\n";
    std::cerr << "  • Attackers CAN detect duplicate files\n";
    std::cerr << "  • Attackers CAN perform equality testing\n";
    std::cerr << "  • Known-plaintext attacks are EASIER\n";
    std::cerr << "\n";
    std::cerr << "USE ONLY IF:\n";
    std::cerr << "  • You need backup deduplication\n";
    std::cerr << "  • You need searchable encryption\n";
    std::cerr << "  • You FULLY UNDERSTAND the risks\n";
    std::cerr << "\n";
    std::cerr << "DEFAULT MODE (random salt) is MUCH MORE SECURE.\n";
    std::cerr << "\n";
    std::cerr << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
    std::cerr << "\n";

    std::cout << "Type 'I UNDERSTAND THE RISKS' to proceed: " << std::flush;
    std::string response;
    std::getline(std::cin, response);

    if (response == "I UNDERSTAND THE RISKS") {
        std::cerr << "\n[OK] Proceeding with deterministic mode (NOT RECOMMENDED)\n\n";
        return true;
    }
    std::cerr << "\n[ABORT] Aborting. Use default mode for better security.\n";
    return false;
}

// ── main ──────────────────────────────────────────────────────────────────────

int main(int argc, char** argv) {
    if (sodium_init() < 0) {
        std::cerr << "Fatal: libsodium initialization failed\n";
        return 99;
    }

    try {
        if (argc < 2) {
            show_usage();
            return 0;
        }

        std::string cmd = argv[1];

        if (cmd == "--help" || cmd == "-h") {
            show_usage();
            return 0;
        }

        if (cmd == "test") {
            std::cout << "Running self-tests...\n";
            if (self_test()) {
                std::cout << "All tests passed!\n";
                return 0;
            } else {
                std::cerr << "Tests failed\n";
                return 1;
            }
        }

        // ── Parse options ─────────────────────────────────────────────────────
        std::string input, output, keyfile_path;
        std::string enc_mode_str = "standard";
        bool keep_original = false;
        bool do_verify     = true;
        bool deterministic = false;
        uint32_t argon_t   = ARGON_T_DEFAULT;
        uint32_t argon_m   = ARGON_M_DEFAULT;
        uint32_t argon_p   = ARGON_P_DEFAULT;

        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];

            if      ((arg == "--output" || arg == "-o")  && i+1 < argc) { output       = argv[++i]; }
            else if (arg == "--keyfile"                  && i+1 < argc) { keyfile_path = argv[++i]; }
            else if ((arg == "--mode"   || arg == "-m")  && i+1 < argc) { enc_mode_str = argv[++i]; }
            else if (arg == "--keep"    || arg == "-k")                 { keep_original = true;      }
            else if (arg == "--no-verify")                              { do_verify    = false;      }
            else if (arg == "--deterministic")                          { deterministic = true;      }
            else if (arg == "--argon-time"               && i+1 < argc) { argon_t = static_cast<uint32_t>(std::stoul(argv[++i])); }
            else if (arg == "--argon-mem"                && i+1 < argc) { argon_m = static_cast<uint32_t>(std::stoul(argv[++i])) * 1024; }
            else if (arg == "--argon-threads"            && i+1 < argc) { argon_p = static_cast<uint32_t>(std::stoul(argv[++i])); }
            else if (arg[0] != '-')                                     { input = arg;              }
        }

        if (input.empty()) {
            std::cerr << "Error: no input file or directory specified\n";
            return 1;
        }

        // ── Parse encryption mode ─────────────────────────────────────────────
        EncryptionMode enc_mode;
        if      (enc_mode_str == "standard")  enc_mode = EncryptionMode::STANDARD;
        else if (enc_mode_str == "split-key") enc_mode = EncryptionMode::SPLIT_KEY;
        else if (enc_mode_str == "key-only")  enc_mode = EncryptionMode::KEY_ONLY;
        else if (enc_mode_str == "headerless")enc_mode = EncryptionMode::HEADERLESS;
        else {
            std::cerr << "Error: unknown mode '" << enc_mode_str << "'\n";
            return 1;
        }

        // ── Load keyfile ──────────────────────────────────────────────────────
        std::vector<uint8_t> keyfile_data;
        if (!keyfile_path.empty()) {
            std::ifstream kf(keyfile_path, std::ios::binary);
            if (!kf) {
                throw CryptoException(ErrorCode::FILE_NOT_FOUND,
                    "keyfile not found: " + keyfile_path);
            }
            keyfile_data.assign(std::istreambuf_iterator<char>(kf),
                                std::istreambuf_iterator<char>());
            std::cout << "Using keyfile: " << keyfile_path << "\n";
        }

        // ── Validate mode + keyfile ───────────────────────────────────────────
        if (enc_mode == EncryptionMode::KEY_ONLY && keyfile_data.empty()) {
            std::cerr << "Error: KEY-ONLY mode requires --keyfile\n";
            return 1;
        }
        if (enc_mode == EncryptionMode::SPLIT_KEY && keyfile_data.empty()) {
            std::cerr << "Error: SPLIT-KEY mode requires --keyfile\n";
            return 1;
        }

        // ── info ──────────────────────────────────────────────────────────────
        if (cmd == "info") {
            show_info(input);
            return 0;
        }

        // ── lock (encrypt) ────────────────────────────────────────────────────
        if (cmd == "lock") {
            const bool input_is_dir = is_directory(input);

            if (output.empty()) {
                // Strip trailing slash for directories
                std::string base = input;
                while (!base.empty() && base.back() == '/') base.pop_back();
                output = base + ".mcc";
            }

            std::cout << "Input    : " << input
                      << (input_is_dir ? " (directory)" : " (file)") << "\n";
            std::cout << "Output   : " << output << "\n";
            std::cout << "Mode     : " << enc_mode_str;
            if (deterministic) std::cout << " (DETERMINISTIC)";
            std::cout << "\n";
            std::cout << "Argon2   : t=" << argon_t
                      << ", m=" << (argon_m / 1024) << "MB"
                      << ", p=" << argon_p << "\n";

            // Get password
            SecureString password;
            if (enc_mode != EncryptionMode::KEY_ONLY) {
                password = get_password_interactive(/*confirm=*/true);
            }

            // Build params
            EncryptParams params;
            params.mode            = enc_mode;
            params.argon_time      = argon_t;
            params.argon_mem_kb    = argon_m;
            params.argon_threads   = argon_p;
            params.keyfile         = keyfile_data.empty() ? nullptr : &keyfile_data;
            params.deterministic_salt = deterministic;
            if (deterministic) {
                params.deterministic_confirm_callback = deterministic_confirmation;
            }

            // Progress bar (size unknown for directories until packed)
            uint64_t total_size = 0;
            if (!input_is_dir) {
                std::ifstream sz(input, std::ios::binary);
                sz.seekg(0, std::ios::end);
                total_size = static_cast<uint64_t>(sz.tellg());
            }
            ProgressBar progress(total_size);
            params.progress_callback = [&progress](uint64_t bytes) {
                progress.update(bytes);
            };

            // Encrypt
            if (input_is_dir) {
                encrypt_directory(input, output, password, params);
            } else {
                encrypt_file(input, output, password, params);
            }
            progress.finish();

            // Verify (only for single files — directory archives are always verified
            // by the encrypt_directory pipeline itself)
            if (do_verify && !input_is_dir) {
                std::cout << "Verifying encryption... " << std::flush;

                DecryptParams dp;
                dp.mode         = enc_mode;
                dp.argon_time   = argon_t;
                dp.argon_mem_kb = argon_m;
                dp.argon_threads = argon_p;
                dp.keyfile      = params.keyfile;

                if (verify_encryption(input, output, password, dp)) {
                    std::cout << "[OK]\n";
                } else {
                    std::cerr << "[FAIL] Verification FAILED\n";
                    return 4;
                }
            }

            std::cout << "Encrypted: " << output << "\n";

            if (deterministic) {
                std::cerr << "\n[WARNING] File encrypted in DETERMINISTIC mode\n";
                std::cerr << "    Re-encrypting the same file will produce IDENTICAL ciphertext\n";
            }

            // Optional deletion
            if (keep_original) {
                std::cout << "Original kept: " << input << "\n";
            } else {
                std::cout << "Delete original securely? [y/N] " << std::flush;
                std::string resp;
                std::getline(std::cin, resp);
                if (!resp.empty() && (resp[0] == 'y' || resp[0] == 'Y')) {
                    if (input_is_dir) {
                        // Recursively shred each file in directory
                        auto files = collect_files(input);
                        for (const auto& rel : files) {
                            secure_delete(input + "/" + rel);
                        }
                        // Best-effort remove empty dirs (rmdir doesn't recurse)
                        std::cout << "Note: Empty directory structure left — remove manually\n";
                    } else {
                        secure_delete(input);
                    }
                } else {
                    std::cout << "Original kept: " << input << "\n";
                }
            }

            return 0;
        }

        // ── unlock (decrypt) ──────────────────────────────────────────────────
        if (cmd == "unlock") {
            if (output.empty()) {
                // Default output: strip .mcc, or append .decrypted
                output = input;
                if (output.size() > 4 &&
                    output.substr(output.size() - 4) == ".mcc") {
                    output = output.substr(0, output.size() - 4);
                } else {
                    output += ".decrypted";
                }
            }

            // Get password
            SecureString password;
            if (enc_mode != EncryptionMode::KEY_ONLY) {
                password = get_password_interactive(/*confirm=*/false);
            }

            // Build params
            DecryptParams params;
            params.mode         = enc_mode;
            params.argon_time   = argon_t;
            params.argon_mem_kb = argon_m;
            params.argon_threads = argon_p;
            params.keyfile      = keyfile_data.empty() ? nullptr : &keyfile_data;

            ProgressBar progress(0);  // size unknown until header read
            params.progress_callback = [&progress](uint64_t bytes) {
                progress.update(bytes);
            };

            // Try to detect if this is a directory archive by peeking metadata
            bool is_dir_archive = false;
            try {
                // If decryption would produce a directory archive, the user must
                // supply --output pointing to a directory name.  We detect this by
                // checking whether the output path already exists as a directory.
                // For now we rely on the user supplying a meaningful --output.
                is_dir_archive = is_directory(output);
            } catch (...) {}

            // Decrypt
            // If the user supplied an output path that doesn't exist yet and the
            // archive contains a directory, decrypt_directory will create it.
            // If it's a regular file archive, decrypt_file produces a file.
            // We try directory-aware decryption when --output ends with no extension
            // or when the target is an existing directory.
            bool try_dir = is_dir_archive ||
                           (!output.empty() && output.back() == '/');

            if (try_dir) {
                decrypt_directory(input, output, password, params);
                std::cout << "Decrypted directory: " << output << "\n";
            } else {
                // Attempt plain file decryption; if that fails with CORRUPTED_FILE
                // it might be a directory archive — let the error propagate.
                decrypt_file(input, output, password, params);
                std::cout << "Decrypted: " << output << "\n";
            }
            progress.finish();

            return 0;
        }

        std::cerr << "Error: unknown command '" << cmd << "'\n";
        show_usage();
        return 1;

    } catch (const CryptoException& e) {
        std::cerr << "\n[ERROR] ";
        switch (e.get_code()) {
        case ErrorCode::FILE_NOT_FOUND:
            std::cerr << "File not found: " << e.what() << "\n";
            return 1;
        case ErrorCode::WRONG_PASSWORD:
        case ErrorCode::AUTH_FAILED:
            std::cerr << "Authentication failed: " << e.what() << "\n";
            return 2;
        case ErrorCode::CORRUPTED_FILE:
            std::cerr << "File corrupted or invalid format: " << e.what() << "\n";
            return 3;
        case ErrorCode::VERIFICATION_FAILED:
            std::cerr << "Verification failed\n";
            return 4;
        case ErrorCode::PERMISSION_DENIED:
            std::cerr << "Permission denied: " << e.what() << "\n";
            return 5;
        case ErrorCode::INVALID_MODE:
            std::cerr << "Invalid mode: " << e.what() << "\n";
            return 6;
        case ErrorCode::DETERMINISTIC_MODE_DECLINED:
            std::cerr << "Deterministic mode declined (smart choice!)\n";
            return 7;
        default:
            std::cerr << "Error: " << e.what() << "\n";
            return 99;
        }
    } catch (const std::exception& e) {
        std::cerr << "\n[FATAL] " << e.what() << "\n";
        return 99;
    }

    return 0;
}