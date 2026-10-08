#ifndef MINICRYPTO_DIR_OPS_H
#define MINICRYPTO_DIR_OPS_H

#include "crypto.h"
#include <string>
#include <vector>
#include <functional>
#include <cstdint>

namespace minicrypto {

// ── Directory archive support ─────────────────────────────────────────────────
//
// A directory is first packed into a simple streaming archive format and then
// passed through the same encrypt_file / decrypt_file pipeline.
//
// Archive format (little-endian, no padding):
//   [4]  magic   = 0x4D434441  "MCDA"
//   [4]  version = 1
//   Per entry:
//     [2]  path_len   (uint16_t)
//     [N]  path       (UTF-8 relative path, no leading '/')
//     [8]  file_size  (uint64_t)
//     [M]  file_data
//   End marker:
//     [2]  path_len = 0
// ─────────────────────────────────────────────────────────────────────────────

constexpr uint32_t ARCHIVE_MAGIC   = 0x4D434441;  // "MCDA"
constexpr uint32_t ARCHIVE_VERSION = 1;

/// Pack all files in `dir_path` (recursively) into a single archive written to
/// `archive_path`.  Calls `progress` with (bytes_written) whenever a chunk is
/// flushed; may be nullptr.
void pack_directory(
    const std::string& dir_path,
    const std::string& archive_path,
    std::function<void(uint64_t)> progress = nullptr
);

/// Unpack an archive produced by pack_directory into `out_dir`.
/// `out_dir` is created if it does not exist.
void unpack_directory(
    const std::string& archive_path,
    const std::string& out_dir,
    std::function<void(uint64_t)> progress = nullptr
);

// ── High-level wrappers ───────────────────────────────────────────────────────

/// Encrypt an entire directory: pack → encrypt (single .mcc file).
void encrypt_directory(
    const std::string& dir_path,
    const std::string& output_path,
    const SecureString& password,
    const EncryptParams& params
);

/// Decrypt a directory archive: decrypt → unpack.
void decrypt_directory(
    const std::string& input_path,
    const std::string& out_dir,
    const SecureString& password,
    const DecryptParams& params
);

/// Returns true if path is an existing directory.
bool is_directory(const std::string& path);

/// Returns true if path is an existing regular file.
bool is_regular_file(const std::string& path);

/// Collect all file paths inside dir (recursively), relative to dir.
std::vector<std::string> collect_files(const std::string& dir_path);

/// Recursively remove a directory and its contents.
void remove_directory_recursive(const std::string& path);

} // namespace minicrypto

#endif // MINICRYPTO_DIR_OPS_H
