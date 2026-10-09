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
#include <filesystem>
#include <limits>

using namespace minicrypto;

// ── Usage ─────────────────────────────────────────────────────────────────────

static void show_usage() {
    std::cout << R"(
MiniCrypto v2.1 — Secure file & directory encryption

USAGE:
  minicrypto lock   <file|dir>   Encrypt file or directory
  minicrypto unlock <file>       Decrypt file (or directory archive)
    minicrypto verify <file>        Verify encrypted file integrity
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

    # Verify an encrypted backup without keeping decrypted output
    minicrypto verify backup.mcc

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
        std::cerr << "\n" << colorize("[OK]", TerminalColor::GREEN, true)
              << " Proceeding with deterministic mode (NOT RECOMMENDED)\n\n";
        return true;
    }
    std::cerr << "\n" << colorize("[ABORT]", TerminalColor::RED, true)
              << " Aborting. Use default mode for better security.\n";
    return false;
}

static std::string make_verify_temp_path(const std::string& input) {
    unsigned char random_suffix[16];
    char suffix_hex[33];
    randombytes_buf(random_suffix, sizeof(random_suffix));
    sodium_bin2hex(suffix_hex, sizeof(suffix_hex), random_suffix, sizeof(random_suffix));
    return input + ".verify_tmp." + suffix_hex;
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

        // ── verify encrypted file integrity ───────────────────────────────────
        if (cmd == "verify") {
            SecureString password;
            if (enc_mode != EncryptionMode::KEY_ONLY) {
                password = get_password_interactive(/*confirm=*/false);
            }

            DecryptParams params;
            params.mode          = enc_mode;
            params.argon_time    = argon_t;
            params.argon_mem_kb  = argon_m;
            params.argon_threads = argon_p;
            params.keyfile       = keyfile_data.empty() ? nullptr : &keyfile_data;

            const std::string temp_decrypt = make_verify_temp_path(input);
            try {
                // Decrypting the complete stream verifies every authentication tag.
                decrypt_file(input, temp_decrypt, password, params);
                secure_delete(temp_decrypt);
            } catch (...) {
                secure_delete(temp_decrypt);
                throw;
            }

            std::cout << colorize("[OK]", TerminalColor::GREEN)
                      << " Integrity verified: " << input << "\n";
            return 0;
        }

        // ── lock (encrypt) ────────────────────────────────────────────────────
        if (cmd == "lock") {
            const bool input_is_dir = is_directory(input);
            const bool output_was_specified = !output.empty();

            if (output.empty()) {
                // Strip trailing slash for directories
                std::string base = input;
                while (!base.empty() && base.back() == '/') base.pop_back();
                output = base + ".mcc";
            }

            if (input_is_dir && !output_was_specified) {
                warn("default archive path is next to the source directory: " + output
                    + "; use --output to choose another location");
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

            // Calculate total source size before packing so directory encryption
            // can use the same progress bar as single-file encryption.
            uint64_t total_size = 0;
            if (input_is_dir) {
                const std::filesystem::path base(input);
                for (const auto& rel : collect_files(input)) {
                    std::error_code ec;
                    const uintmax_t file_size = std::filesystem::file_size(base / rel, ec);
                    if (ec) {
                        throw CryptoException(ErrorCode::IO_ERROR,
                            "cannot determine file size: " + (base / rel).string()
                            + " (" + ec.message() + ")");
                    }
                    if (file_size > std::numeric_limits<uint64_t>::max() - total_size) {
                        throw CryptoException(ErrorCode::IO_ERROR,
                            "total directory size exceeds supported range: " + input);
                    }
                    total_size += static_cast<uint64_t>(file_size);
                }
            } else {
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
                    std::cout << colorize("[OK]", TerminalColor::GREEN) << "\n";
                } else {
                    std::cerr << colorize("[FAIL]", TerminalColor::RED)
                              << " Verification FAILED\n";
                    return 4;
                }
            }

            std::cout << "Encrypted: " << output << "\n";

            if (deterministic) {
                std::cerr << "\n" << colorize("[WARNING]", TerminalColor::YELLOW, true)
                          << " File encrypted in DETERMINISTIC mode\n";
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
                        // Shred all files, then remove empty directory skeleton
                        auto files = collect_files(input);
                        for (const auto& rel : files) {
                            secure_delete(input + "/" + rel);
                        }
                        remove_directory_recursive(input);
                        std::cout << "Deleted: " << input << "\n";
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
            const bool output_was_specified = !output.empty();
            if (output.empty()) {
                // Default output: strip .mcc suffix, otherwise append .decrypted
                output = input;
                if (output.size() > 4 &&
                    output.substr(output.size() - 4) == ".mcc") {
                    output = output.substr(0, output.size() - 4);
                } else {
                    output += ".decrypted";
                }
            }
            // Normalise output path by removing a trailing slash.
            while (output.size() > 1 && output.back() == '/') output.pop_back();

            // Get password
            SecureString password;
            if (enc_mode != EncryptionMode::KEY_ONLY) {
                password = get_password_interactive(/*confirm=*/false);
            }

            // Build params
            DecryptParams params;
            params.mode          = enc_mode;
            params.argon_time    = argon_t;
            params.argon_mem_kb  = argon_m;
            params.argon_threads = argon_p;
            params.keyfile       = keyfile_data.empty() ? nullptr : &keyfile_data;

            ProgressBar progress(0);  // plaintext size unknown until header is read
            params.progress_callback = [&progress](uint64_t bytes) {
                progress.update(bytes);
            };

            // Step 1: decrypt into a temporary file
            std::string tmp_dec = input + ".dec_tmp";
            try {
                decrypt_file(input, tmp_dec, password, params);
                progress.finish();

                // Step 2: peek first 4 bytes to detect MCDA archive magic
                bool is_dir_archive = false;
                {
                    std::ifstream f(tmp_dec, std::ios::binary);
                    if (f) {
                        uint8_t buf[4] = {};
                        f.read(reinterpret_cast<char*>(buf), 4);
                        if (f.gcount() == 4) {
                            uint32_t magic =
                                static_cast<uint32_t>(buf[0])
                              | (static_cast<uint32_t>(buf[1]) << 8)
                              | (static_cast<uint32_t>(buf[2]) << 16)
                              | (static_cast<uint32_t>(buf[3]) << 24);
                            is_dir_archive = (magic == ARCHIVE_MAGIC);
                        }
                    }
                }

                // Step 3a: unpack directory archive
                if (is_dir_archive) {
                    if (!output_was_specified) {
                        output += ".restored";
                    }
                    unpack_directory(tmp_dec, output);
                    std::error_code ec;
                    std::filesystem::remove(tmp_dec, ec);
                    std::cout << "Decrypted directory: " << output << "\n";
                } else {
                    // Step 3b: plain file — rename temp to final output
                    std::error_code ec;
                    std::filesystem::rename(tmp_dec, output, ec);
                    if (ec) {
                        // Cross-device rename fallback
                        std::filesystem::copy_file(tmp_dec, output,
                            std::filesystem::copy_options::overwrite_existing, ec);
                        std::filesystem::remove(tmp_dec, ec);
                        if (ec) throw CryptoException(ErrorCode::IO_ERROR,
                            "cannot write output: " + output);
                    }
                    std::cout << "Decrypted: " << output << "\n";
                }
            } catch (...) {
                std::error_code ec;
                std::filesystem::remove(tmp_dec, ec);
                throw;
            }

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