#include "../core/crypto.h"
#include "../core/deniable.h"
#include "../core/dir_ops.h"
#include "../core/file_ops.h"
#include "../core/format.h"
#include "../ui_cli/ui.h"

#include <sodium.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

using namespace minicrypto;

// ── Usage ─────────────────────────────────────────────────────────────────────

static void show_usage() {
  std::cout << R"(
MiniCrypto v1.2 — Secure file & directory encryption

USAGE:
  minicrypto lock   <file|dir>   Encrypt file or directory
  minicrypto unlock <file>       Decrypt file (or directory archive)
  minicrypto verify <file>       Verify encrypted file integrity
  minicrypto info   <file>       Show encrypted-file metadata
  minicrypto container-create <cover> --output <container> [--hidden <hidden>]
                                 Create experimental fixed-slot container
  minicrypto container-open   <container> --output <output>
                                 Open matching fixed-slot container slot
  minicrypto test                Run built-in self-tests

ENCRYPTION MODES:
  --mode standard      [DEFAULT] Password only
  --mode split-key     Password + keyfile (both required)
  --mode key-only      Keyfile only (no password)
  --mode headerless    Minimal header, raw stream

OPTIONS:
  --output <path>       Output file (or directory for unlock of dir archive)
  --keyfile <file>      Key file path
  --hidden <file>       Hidden slot input file for container-create
  --slot-size <mb>      Slot size in MB for container-create (1-64, default: 16)
  --keep                Keep source file/directory after encryption
  --no-verify           Skip post-encryption verification
  --argon-time <n>      Argon2 iterations (default: 3)
  --argon-mem <mb>      Argon2 memory in MB (default: 128)
  --argon-threads <n>   Argon2 parallelism (default: 2)

DANGEROUS OPTIONS:
  --deterministic       [WARNING] FOOTGUN: Deterministic encryption
                        Same file + password = same ciphertext.
                        Leaks equality of plaintexts and links between copies!
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

  # Show file metadata
  minicrypto info secret.txt.mcc

  # Split-key mode (password + keyfile)
  minicrypto lock secret.txt --mode split-key --keyfile ~/usb.key

  # Key-only mode (no password, keyfile only)
  minicrypto lock secret.txt --mode key-only --keyfile ~/master.key

  # Headerless mode (minimal header)
  minicrypto lock secret.txt --mode headerless

  # Create fixed-slot container (experimental)
  minicrypto container-create cover.txt --hidden secret.txt --output vault.bin

  # Open fixed-slot container
  minicrypto container-open vault.bin --output extracted.txt

  # Deterministic mode (DANGEROUS — deduplication only)
  minicrypto lock backup.tar --deterministic

SECURITY:
  - XChaCha20-Poly1305 stream encryption
  - Argon2id key derivation
  - Authenticated chunk encryption (AEAD per chunk; header fields unauthenticated)
  - Memory locking (mlock) for sensitive buffers (best-effort)
  - Best-effort atomic writes (write-then-rename)
  - Secure deletion (3-pass overwrite, best-effort)

)" << std::flush;
}

// ── Info ──────────────────────────────────────────────────────────────────────

static void show_info(const std::filesystem::path& path) {
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
        std::cout << "HEADERLESS (minimal header)\n";
        break;
      }
      std::cout << "  Original size  : " << meta.plaintext_size << " bytes\n";
      std::cout << "  Encryption     : XChaCha20-Poly1305\n";
      std::cout << "  KDF            : Argon2id\n";
      std::cout << "    Time         : " << meta.argon_time << " iterations\n";
      std::cout << "    Memory       : " << (meta.argon_mem_kb / 1024) << " MB\n";
      std::cout << "    Threads      : " << meta.argon_threads << "\n";
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
  std::cerr << "  • Leaks equality of plaintexts and links between copies\n";
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
    std::cerr << "\n"
              << colorize("[OK]", TerminalColor::GREEN, true)
              << " Proceeding with deterministic mode (NOT RECOMMENDED)\n\n";
    return true;
  }
  std::cerr << "\n"
            << colorize("[ABORT]", TerminalColor::RED, true)
            << " Aborting. Use default mode for better security.\n";
  return false;
}

static std::filesystem::path make_verify_temp_path(const std::filesystem::path& input) {
  unsigned char random_suffix[16];
  char suffix_hex[33];
  randombytes_buf(random_suffix, sizeof(random_suffix));
  sodium_bin2hex(suffix_hex, sizeof(suffix_hex), random_suffix, sizeof(random_suffix));
  std::filesystem::path temp = input;
  temp += ".verify_tmp.";
  temp += suffix_hex;
  return temp;
}

static std::filesystem::path path_from_cli_arg(const std::string& value) {
#ifdef _WIN32
  return std::filesystem::u8path(value);
#else
  return std::filesystem::path(value);
#endif
}

// ── CLI Options and Argument Helpers ─────────────────────────────────────────

struct CliOptions {
  std::filesystem::path input;
  std::filesystem::path output;
  std::filesystem::path keyfile_path;
  std::filesystem::path hidden_path;
  std::string enc_mode_str = "standard";
  EncryptionMode enc_mode = EncryptionMode::STANDARD;
  std::vector<uint8_t> keyfile_data;
  bool keep_original = false;
  bool do_verify = true;
  bool deterministic = false;
  uint32_t argon_t = ARGON_T_DEFAULT;
  uint32_t argon_m = ARGON_M_DEFAULT;
  uint32_t argon_p = ARGON_P_DEFAULT;
  uint64_t slot_size_bytes = 16ULL * 1024ULL * 1024ULL;
};

static bool parse_uint32_arg(const std::string& opt, const std::string& val, uint32_t& out) {
  try {
    size_t idx = 0;
    unsigned long v = std::stoul(val, &idx);
    if (idx != val.size() || v > std::numeric_limits<uint32_t>::max()) {
      std::cerr << "Error: invalid value for " << opt << ": " << val << "\n";
      return false;
    }
    out = static_cast<uint32_t>(v);
    return true;
  } catch (...) {
    std::cerr << "Error: invalid numeric value for " << opt << ": " << val << "\n";
    return false;
  }
}

static bool parse_slot_size_arg(const std::string& val, uint64_t& out_bytes) {
  try {
    size_t idx = 0;
    unsigned long long v = std::stoull(val, &idx);
    if (idx != val.size()) {
      std::cerr << "Error: invalid value for --slot-size: " << val << "\n";
      return false;
    }
    if (v <= 64) {
      out_bytes = v * 1024ULL * 1024ULL;
    } else {
      out_bytes = v;
    }
    return true;
  } catch (...) {
    std::cerr << "Error: invalid numeric value for --slot-size: " << val << "\n";
    return false;
  }
}

// ── Command Handlers ──────────────────────────────────────────────────────────

static int handle_container_create(const CliOptions& opt) {
  if (opt.output.empty()) {
    std::cerr << "Error: container-create requires --output <file>\n";
    return 1;
  }
  DeniableContainerOptions opts;
  opts.slot_size_bytes = opt.slot_size_bytes;
  opts.argon_time      = opt.argon_t;
  opts.argon_mem_kb    = opt.argon_m;
  opts.argon_threads   = opt.argon_p;

  SecureString cover_pass = get_password_interactive(true, "cover password");
  if (!opt.hidden_path.empty()) {
    SecureString hidden_pass = get_password_interactive(true, "hidden password");
    create_deniable_container(opt.input, &opt.hidden_path, opt.output, cover_pass, &hidden_pass, opts);
  } else {
    create_deniable_container(opt.input, nullptr, opt.output, cover_pass, nullptr, opts);
  }
  std::cout << colorize("[OK]", TerminalColor::GREEN)
            << " Created container: " << opt.output.u8string() << "\n";
  return 0;
}

static int handle_container_open(const CliOptions& opt) {
  if (opt.output.empty()) {
    std::cerr << "Error: container-open requires --output <file>\n";
    return 1;
  }
  DeniableContainerOptions opts;
  opts.slot_size_bytes = opt.slot_size_bytes;
  opts.argon_time      = opt.argon_t;
  opts.argon_mem_kb    = opt.argon_m;
  opts.argon_threads   = opt.argon_p;

  SecureString pass = get_password_interactive(false, "password");
  open_deniable_container(opt.input, opt.output, pass, opts);
  std::cout << colorize("[OK]", TerminalColor::GREEN)
            << " Decrypted container slot to: " << opt.output.u8string() << "\n";
  return 0;
}

static int handle_verify(const CliOptions& opt) {
  SecureString password;
  if (opt.enc_mode != EncryptionMode::KEY_ONLY) {
    password = get_password_interactive(/*confirm=*/false);
  }

  DecryptParams params;
  params.mode          = opt.enc_mode;
  params.argon_time    = opt.argon_t;
  params.argon_mem_kb  = opt.argon_m;
  params.argon_threads = opt.argon_p;
  params.keyfile       = opt.keyfile_data.empty() ? nullptr : &opt.keyfile_data;

  const std::filesystem::path temp_decrypt = make_verify_temp_path(opt.input);
  try {
    // Decrypting the complete stream verifies every authentication tag.
    decrypt_file(opt.input, temp_decrypt, password, params);
    secure_delete(temp_decrypt);
  } catch (...) {
    secure_delete(temp_decrypt);
    throw;
  }

  std::cout << colorize("[OK]", TerminalColor::GREEN)
            << " Integrity verified: " << opt.input.u8string() << "\n";
  return 0;
}

static int handle_lock(CliOptions opt) {
  const bool input_is_dir = minicrypto::is_directory(opt.input);
  const bool output_was_specified = !opt.output.empty();

  if (opt.output.empty()) {
    // Strip trailing slash for directories
    std::filesystem::path base = opt.input;
    while (base != base.root_path() && base.filename().empty()) {
      base = base.parent_path();
    }
    opt.output = base;
    opt.output += ".mcc";
  }

  if (input_is_dir && !output_was_specified) {
    warn("default archive path is next to the source directory: " +
         opt.output.u8string() + "; use --output to choose another location");
  }

  std::cout << "Input    : " << opt.input.u8string()
            << (input_is_dir ? " (directory)" : " (file)") << "\n";
  std::cout << "Output   : " << opt.output.u8string() << "\n";
  std::cout << "Mode     : " << opt.enc_mode_str;
  if (opt.deterministic) std::cout << " (DETERMINISTIC)";
  std::cout << "\n";
  std::cout << "Argon2   : t=" << opt.argon_t
            << ", m=" << (opt.argon_m / 1024) << "MB"
            << ", p=" << opt.argon_p << "\n";

  // Get password
  SecureString password;
  if (opt.enc_mode != EncryptionMode::KEY_ONLY) {
    password = get_password_interactive(/*confirm=*/true);
  }

  // Build params
  EncryptParams params;
  params.mode            = opt.enc_mode;
  params.argon_time      = opt.argon_t;
  params.argon_mem_kb    = opt.argon_m;
  params.argon_threads   = opt.argon_p;
  params.keyfile         = opt.keyfile_data.empty() ? nullptr : &opt.keyfile_data;
  params.deterministic_salt = opt.deterministic;
  if (opt.deterministic) {
    params.deterministic_confirm_callback = deterministic_confirmation;
  }

  // Calculate total source size before packing
  uint64_t total_size = 0;
  if (input_is_dir) {
    const std::filesystem::path base(opt.input);
    for (const auto& rel : collect_files(opt.input)) {
      std::error_code ec;
      const uintmax_t file_size = std::filesystem::file_size(base / rel, ec);
      if (ec) {
        throw CryptoException(
            ErrorCode::IO_ERROR,
            "cannot determine file size: " + (base / rel).u8string() +
                " (" + ec.message() + ")");
      }
      if (file_size > std::numeric_limits<uint64_t>::max() - total_size) {
        throw CryptoException(
            ErrorCode::IO_ERROR,
            "total directory size exceeds supported range: " + opt.input.u8string());
      }
      total_size += static_cast<uint64_t>(file_size);
    }
  } else {
    std::ifstream sz(opt.input, std::ios::binary);
    sz.seekg(0, std::ios::end);
    total_size = static_cast<uint64_t>(sz.tellg());
  }

  ProgressBar progress(total_size);
  params.progress_callback = [&progress](uint64_t bytes) {
    progress.update(bytes);
  };

  // Encrypt
  if (input_is_dir) {
    encrypt_directory(opt.input, opt.output, password, params);
  } else {
    encrypt_file(opt.input, opt.output, password, params);
  }
  progress.finish();

  // Verify (only for single files — directory archives are verified by encrypt_directory)
  if (opt.do_verify && !input_is_dir) {
    std::cout << "Verifying encryption... " << std::flush;

    DecryptParams dp;
    dp.mode          = opt.enc_mode;
    dp.argon_time    = opt.argon_t;
    dp.argon_mem_kb  = opt.argon_m;
    dp.argon_threads = opt.argon_p;
    dp.keyfile       = params.keyfile;

    if (verify_encryption(opt.input, opt.output, password, dp)) {
      std::cout << colorize("[OK]", TerminalColor::GREEN) << "\n";
    } else {
      std::cerr << colorize("[FAIL]", TerminalColor::RED)
                << " Verification FAILED\n";
      return 4;
    }
  }

  std::cout << "Encrypted: " << opt.output << "\n";

  if (opt.deterministic) {
    std::cerr << "\n"
              << colorize("[WARNING]", TerminalColor::YELLOW, true)
              << " File encrypted in DETERMINISTIC mode\n";
    std::cerr << "    Re-encrypting the same file will produce IDENTICAL ciphertext\n";
  }

  // Optional deletion
  if (opt.keep_original) {
    std::cout << "Original kept: " << opt.input.u8string() << "\n";
  } else {
    std::cout << "Delete original securely? [y/N] " << std::flush;
    std::string resp;
    std::getline(std::cin, resp);
    if (!resp.empty() && (resp[0] == 'y' || resp[0] == 'Y')) {
      if (input_is_dir) {
        auto files = collect_files(opt.input);
        for (const auto& rel : files) {
          secure_delete(opt.input / rel);
        }
        remove_directory_recursive(opt.input);
        std::cout << "Deleted: " << opt.input.u8string() << "\n";
      } else {
        secure_delete(opt.input);
      }
    } else {
      std::cout << "Original kept: " << opt.input.u8string() << "\n";
    }
  }

  return 0;
}

static int handle_unlock(CliOptions opt) {
  const bool output_was_specified = !opt.output.empty();
  if (opt.output.empty()) {
    opt.output = opt.input;
    if (opt.output.extension().u8string() == ".mcc") {
      opt.output.replace_extension();
    } else {
      opt.output += ".decrypted";
    }
  }
  // Normalise output path by removing a trailing slash
  if (opt.output != opt.output.root_path() && opt.output.filename().empty()) {
    opt.output = opt.output.parent_path();
  }

  // Get password
  SecureString password;
  if (opt.enc_mode != EncryptionMode::KEY_ONLY) {
    password = get_password_interactive(/*confirm=*/false);
  }

  DecryptParams params;
  params.mode          = opt.enc_mode;
  params.argon_time    = opt.argon_t;
  params.argon_mem_kb  = opt.argon_m;
  params.argon_threads = opt.argon_p;
  params.keyfile       = opt.keyfile_data.empty() ? nullptr : &opt.keyfile_data;

  ProgressBar progress(0);
  params.progress_callback = [&progress](uint64_t bytes) {
    progress.update(bytes);
  };

  // Step 1: decrypt into temporary file
  std::filesystem::path tmp_dec = opt.input;
  tmp_dec += ".dec_tmp";
  try {
    decrypt_file(opt.input, tmp_dec, password, params);
    progress.finish();

    // Step 2: peek first 4 bytes to detect MCDA archive magic
    bool is_dir_archive = false;
    {
      std::ifstream f(tmp_dec, std::ios::binary);
      if (f) {
        uint8_t buf[4] = {};
        f.read(reinterpret_cast<char*>(buf), 4);
        if (f.gcount() == 4) {
          uint32_t magic = static_cast<uint32_t>(buf[0]) |
                           (static_cast<uint32_t>(buf[1]) << 8) |
                           (static_cast<uint32_t>(buf[2]) << 16) |
                           (static_cast<uint32_t>(buf[3]) << 24);
          is_dir_archive = (magic == ARCHIVE_MAGIC);
        }
      }
    }

    // Step 3a: unpack directory archive
    if (is_dir_archive) {
      if (!output_was_specified) {
        opt.output += ".restored";
      }
      unpack_directory(tmp_dec, opt.output);
      std::error_code ec;
      std::filesystem::remove(tmp_dec, ec);
      std::cout << "Decrypted directory: " << opt.output.u8string() << "\n";
    } else {
      // Step 3b: plain file — rename temp to final output
      std::error_code ec;
      std::filesystem::rename(tmp_dec, opt.output, ec);
      if (ec) {
        std::filesystem::copy_file(
            tmp_dec, opt.output,
            std::filesystem::copy_options::overwrite_existing, ec);
        std::filesystem::remove(tmp_dec, ec);
        if (ec) {
          throw CryptoException(ErrorCode::IO_ERROR,
                                "cannot write output: " + opt.output.u8string());
        }
      }
      std::cout << "Decrypted: " << opt.output.u8string() << "\n";
    }
  } catch (...) {
    std::error_code ec;
    std::filesystem::remove(tmp_dec, ec);
    throw;
  }

  return 0;
}

// ── main runner ───────────────────────────────────────────────────────────────

static int run_cli(int argc, char** argv) {
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
    CliOptions opt;

    for (int i = 2; i < argc; ++i) {
      std::string arg = argv[i];

      if ((arg == "--output" || arg == "-o") && i + 1 < argc) {
        opt.output = path_from_cli_arg(argv[++i]);
      } else if (arg == "--keyfile" && i + 1 < argc) {
        opt.keyfile_path = path_from_cli_arg(argv[++i]);
      } else if (arg == "--hidden" && i + 1 < argc) {
        opt.hidden_path = path_from_cli_arg(argv[++i]);
      } else if (arg == "--slot-size" && i + 1 < argc) {
        if (!parse_slot_size_arg(argv[++i], opt.slot_size_bytes)) return 1;
      } else if ((arg == "--mode" || arg == "-m") && i + 1 < argc) {
        opt.enc_mode_str = argv[++i];
      } else if (arg == "--keep" || arg == "-k") {
        opt.keep_original = true;
      } else if (arg == "--no-verify") {
        opt.do_verify = false;
      } else if (arg == "--deterministic") {
        opt.deterministic = true;
      } else if (arg == "--argon-time" && i + 1 < argc) {
        if (!parse_uint32_arg("--argon-time", argv[++i], opt.argon_t)) return 1;
      } else if (arg == "--argon-mem" && i + 1 < argc) {
        uint32_t mem_mb = 0;
        if (!parse_uint32_arg("--argon-mem", argv[++i], mem_mb)) return 1;
        opt.argon_m = mem_mb * 1024;
      } else if (arg == "--argon-threads" && i + 1 < argc) {
        if (!parse_uint32_arg("--argon-threads", argv[++i], opt.argon_p)) return 1;
      } else if (arg[0] != '-') {
        opt.input = path_from_cli_arg(arg);
      }
    }

    if (opt.input.empty()) {
      std::cerr << "Error: no input file or directory specified\n";
      return 1;
    }

    // ── Fixed-slot container commands ─────────────────────────────────────
    if (cmd == "container-create") {
      return handle_container_create(opt);
    }
    if (cmd == "container-open") {
      return handle_container_open(opt);
    }

    // ── Parse encryption mode ─────────────────────────────────────────────
    if      (opt.enc_mode_str == "standard")   opt.enc_mode = EncryptionMode::STANDARD;
    else if (opt.enc_mode_str == "split-key")  opt.enc_mode = EncryptionMode::SPLIT_KEY;
    else if (opt.enc_mode_str == "key-only")   opt.enc_mode = EncryptionMode::KEY_ONLY;
    else if (opt.enc_mode_str == "headerless") opt.enc_mode = EncryptionMode::HEADERLESS;
    else {
      std::cerr << "Error: unknown mode '" << opt.enc_mode_str << "'\n";
      return 1;
    }

    // ── Load keyfile ──────────────────────────────────────────────────────
    if (!opt.keyfile_path.empty()) {
      std::ifstream kf(opt.keyfile_path, std::ios::binary);
      if (!kf) {
        throw CryptoException(ErrorCode::FILE_NOT_FOUND,
                              "keyfile not found: " + opt.keyfile_path.u8string());
      }
      opt.keyfile_data.assign(std::istreambuf_iterator<char>(kf),
                              std::istreambuf_iterator<char>());
      std::cout << "Using keyfile: " << opt.keyfile_path.u8string() << "\n";
    }

    // ── Validate mode + keyfile ───────────────────────────────────────────
    if (opt.enc_mode == EncryptionMode::KEY_ONLY && opt.keyfile_data.empty()) {
      std::cerr << "Error: KEY-ONLY mode requires --keyfile\n";
      return 1;
    }
    if (opt.enc_mode == EncryptionMode::SPLIT_KEY && opt.keyfile_data.empty()) {
      std::cerr << "Error: SPLIT-KEY mode requires --keyfile\n";
      return 1;
    }

    // ── Dispatch commands ─────────────────────────────────────────────────
    if (cmd == "info") {
      show_info(opt.input);
      return 0;
    }
    if (cmd == "verify") {
      return handle_verify(opt);
    }
    if (cmd == "lock") {
      return handle_lock(opt);
    }
    if (cmd == "unlock") {
      return handle_unlock(opt);
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

#ifdef _WIN32
static bool wide_to_utf8(const wchar_t* value, std::string& result) {
  const int required = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value,
                                           -1, nullptr, 0, nullptr, nullptr);
  if (required <= 0) return false;

  result.resize(static_cast<size_t>(required));
  if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, -1,
                          result.data(), required, nullptr, nullptr) <= 0) {
    return false;
  }
  result.pop_back();
  return true;
}

int wmain(int argc, wchar_t** argv) {
  std::vector<std::string> utf8_args(static_cast<size_t>(argc));
  std::vector<char*> narrow_argv;
  narrow_argv.reserve(static_cast<size_t>(argc));
  for (int i = 0; i < argc; ++i) {
    if (!wide_to_utf8(argv[i], utf8_args[static_cast<size_t>(i)])) {
      std::cerr << "Failed to convert command-line argument to UTF-8\n";
      return 99;
    }
  }
  for (auto& arg : utf8_args) narrow_argv.push_back(arg.data());
  return run_cli(argc, narrow_argv.data());
}
#else
int main(int argc, char** argv) {
  return run_cli(argc, argv);
}
#endif