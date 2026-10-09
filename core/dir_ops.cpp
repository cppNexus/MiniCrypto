#include "dir_ops.h"
#include "file_ops.h"
#include "format.h"

#include <filesystem>
#include <fstream>
#include <vector>
#include <algorithm>
#include <system_error>
#include <cstdint>
#include <cstring>
#include <set>

namespace fs = std::filesystem;

namespace minicrypto {

// ── Filesystem helpers ────────────────────────────────────────────────────────

bool is_directory(const std::string& path) {
    std::error_code ec;
    return fs::is_directory(path, ec);
}

bool is_regular_file(const std::string& path) {
    std::error_code ec;
    return fs::is_regular_file(path, ec);
}

std::vector<std::string> collect_files(const std::string& dir_path) {
    std::vector<std::string> result;
    std::error_code ec;

    if (!fs::is_directory(dir_path, ec)) {
        throw CryptoException(ErrorCode::FILE_NOT_FOUND,
            "directory not found: " + dir_path);
    }

    fs::path base(dir_path);
    for (const auto& entry : fs::recursive_directory_iterator(base, ec)) {
        if (entry.is_regular_file(ec)) {
            // Compute relative path
            fs::path rel = fs::relative(entry.path(), base, ec);
            result.push_back(rel.generic_string());
        }
    }

    // Sort paths for reproducible archive ordering
    std::sort(result.begin(), result.end());
    return result;
}

void remove_directory_recursive(const std::string& path) {
    std::error_code ec;
    fs::remove_all(path, ec);
}

// ── Little-endian I/O helpers ─────────────────────────────────────────────────

static void write_u16_le(std::ofstream& f, uint16_t v) {
    uint8_t buf[2] = {static_cast<uint8_t>(v), static_cast<uint8_t>(v >> 8)};
    f.write(reinterpret_cast<char*>(buf), 2);
    if (!f) throw CryptoException(ErrorCode::IO_ERROR, "archive write error (u16)");
}

static void write_u32_le(std::ofstream& f, uint32_t v) {
    uint8_t buf[4] = {
        static_cast<uint8_t>(v),
        static_cast<uint8_t>(v >> 8),
        static_cast<uint8_t>(v >> 16),
        static_cast<uint8_t>(v >> 24)
    };
    f.write(reinterpret_cast<char*>(buf), 4);
    if (!f) throw CryptoException(ErrorCode::IO_ERROR, "archive write error (u32)");
}

static void write_u64_le(std::ofstream& f, uint64_t v) {
    uint8_t buf[8];
    for (int i = 0; i < 8; ++i) buf[i] = static_cast<uint8_t>(v >> (8 * i));
    f.write(reinterpret_cast<char*>(buf), 8);
    if (!f) throw CryptoException(ErrorCode::IO_ERROR, "archive write error (u64)");
}

static uint16_t read_u16_le(std::ifstream& f) {
    uint8_t buf[2];
    f.read(reinterpret_cast<char*>(buf), 2);
    if (f.gcount() != 2) throw CryptoException(ErrorCode::CORRUPTED_FILE, "archive truncated (u16)");
    return static_cast<uint16_t>(buf[0]) | (static_cast<uint16_t>(buf[1]) << 8);
}

static uint32_t read_u32_le(std::ifstream& f) {
    uint8_t buf[4];
    f.read(reinterpret_cast<char*>(buf), 4);
    if (f.gcount() != 4) throw CryptoException(ErrorCode::CORRUPTED_FILE, "archive truncated (u32)");
    return static_cast<uint32_t>(buf[0])
         | (static_cast<uint32_t>(buf[1]) << 8)
         | (static_cast<uint32_t>(buf[2]) << 16)
         | (static_cast<uint32_t>(buf[3]) << 24);
}

static uint64_t read_u64_le(std::ifstream& f) {
    uint8_t buf[8];
    f.read(reinterpret_cast<char*>(buf), 8);
    if (f.gcount() != 8) throw CryptoException(ErrorCode::CORRUPTED_FILE, "archive truncated (u64)");
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(buf[i]) << (8 * i);
    return v;
}

// ── Pack / Unpack ─────────────────────────────────────────────────────────────

void pack_directory(
    const std::string& dir_path,
    const std::string& archive_path,
    std::function<void(uint64_t)> progress)
{
    if (!is_directory(dir_path)) {
        throw CryptoException(ErrorCode::FILE_NOT_FOUND,
            "not a directory: " + dir_path);
    }

    std::vector<std::string> files = collect_files(dir_path);
    fs::path base(dir_path);

    // Build set of directories auto-created as parent paths of file entries
    std::set<std::string> file_parent_dirs;
    for (const auto& f : files) {
        for (fs::path cur = fs::path(f).parent_path();
             !cur.empty() && cur.generic_string() != ".";
             cur = cur.parent_path()) {
            file_parent_dirs.insert(cur.generic_string());
        }
    }

    // Collect directories that won't be implicitly recreated (empty dirs)
    std::vector<std::string> empty_dir_entries;
    {
        std::error_code ec;
        for (const auto& entry : fs::recursive_directory_iterator(base, ec)) {
            if (!entry.is_directory(ec)) continue;
            fs::path rel = fs::relative(entry.path(), base, ec);
            std::string rel_str = rel.generic_string();
            if (file_parent_dirs.find(rel_str) == file_parent_dirs.end()) {
                empty_dir_entries.push_back(rel_str + "/");
            }
        }
        std::sort(empty_dir_entries.begin(), empty_dir_entries.end());
    }

    std::ofstream out(archive_path, std::ios::binary);
    if (!out) {
        throw CryptoException(ErrorCode::PERMISSION_DENIED,
            "cannot create archive: " + archive_path);
    }

    // Write header (v2: supports explicit directory entries)
    write_u32_le(out, ARCHIVE_MAGIC);
    write_u32_le(out, ARCHIVE_VERSION);

    uint64_t bytes_written = 8;
    std::vector<char> copy_buf(CHUNK_SIZE);

    // Write explicit directory entries (trailing '/', file_size = 0)
    for (const auto& dir_rel : empty_dir_entries) {
        if (dir_rel.size() > ARCHIVE_MAX_PATH_LEN) {
            throw CryptoException(ErrorCode::IO_ERROR,
                "path too long (>4096): " + dir_rel);
        }
        auto path_len = static_cast<uint16_t>(dir_rel.size());
        write_u16_le(out, path_len);
        out.write(dir_rel.data(), path_len);
        if (!out) throw CryptoException(ErrorCode::IO_ERROR, "archive write error (dir entry)");
        write_u64_le(out, 0);
        bytes_written += 2 + path_len + 8;
        if (progress) progress(bytes_written);
    }

    // Write file entries
    for (const auto& rel : files) {
        fs::path full_path = base / rel;

        if (rel.size() > ARCHIVE_MAX_PATH_LEN) {
            throw CryptoException(ErrorCode::IO_ERROR,
            "path too long (>4096): " + rel);
        }
        uint16_t path_len = static_cast<uint16_t>(rel.size());

        std::ifstream src(full_path, std::ios::binary);
        if (!src) {
            throw CryptoException(ErrorCode::IO_ERROR,
                "cannot read file: " + full_path.string());
        }

        src.seekg(0, std::ios::end);
        uint64_t file_size = static_cast<uint64_t>(src.tellg());
        src.seekg(0);

        // Entry header
        write_u16_le(out, path_len);
        out.write(rel.data(), path_len);
        if (!out) throw CryptoException(ErrorCode::IO_ERROR, "archive write error (path)");
        write_u64_le(out, file_size);

        bytes_written += 2 + path_len + 8;

        // Entry payload
        uint64_t remaining = file_size;
        while (remaining > 0) {
            size_t chunk = static_cast<size_t>(std::min<uint64_t>(remaining, copy_buf.size()));
            src.read(copy_buf.data(), static_cast<std::streamsize>(chunk));
            std::streamsize got = src.gcount();
            if (got <= 0) {
                throw CryptoException(ErrorCode::IO_ERROR,
                    "unexpected EOF reading: " + full_path.string());
            }
            out.write(copy_buf.data(), got);
            if (!out) throw CryptoException(ErrorCode::IO_ERROR, "archive write error (data)");

            remaining -= static_cast<uint64_t>(got);
            bytes_written += static_cast<uint64_t>(got);
            if (progress) progress(bytes_written);
        }
    }

    // End of entries marker
    write_u16_le(out, 0);
    out.flush();
    if (!out) throw CryptoException(ErrorCode::IO_ERROR, "archive flush error");
}

void unpack_directory(
    const std::string& archive_path,
    const std::string& out_dir,
    std::function<void(uint64_t)> progress)
{
    std::ifstream in(archive_path, std::ios::binary);
    if (!in) {
        throw CryptoException(ErrorCode::FILE_NOT_FOUND,
            "archive not found: " + archive_path);
    }

    uint32_t magic   = read_u32_le(in);
    uint32_t version = read_u32_le(in);

    if (magic != ARCHIVE_MAGIC) {
        throw CryptoException(ErrorCode::CORRUPTED_FILE,
            "not a MiniCrypto directory archive (bad magic)");
    }
    if (version < ARCHIVE_VERSION_MIN || version > ARCHIVE_VERSION) {
        throw CryptoException(ErrorCode::CORRUPTED_FILE,
            "unsupported archive version: " + std::to_string(version));
    }

    std::error_code ec;
    fs::path target_base(out_dir);
    fs::create_directories(target_base, ec);
    if (ec) {
        throw CryptoException(ErrorCode::PERMISSION_DENIED,
            "cannot create directory: " + out_dir + " (" + ec.message() + ")");
    }

    std::vector<char> copy_buf(CHUNK_SIZE);
    uint64_t bytes_read = 8;

    while (true) {
        uint16_t path_len = read_u16_le(in);
        if (path_len == 0) break; // End marker
        if (path_len > ARCHIVE_MAX_PATH_LEN) {
            throw CryptoException(ErrorCode::CORRUPTED_FILE,
                "archive path exceeds maximum length (4096 bytes)");
        }

        std::string rel(path_len, '\0');
        in.read(&rel[0], path_len);
        if (in.gcount() != path_len) {
            throw CryptoException(ErrorCode::CORRUPTED_FILE,
                "archive truncated (path data)");
        }

        // Detect directory entry (trailing '/' — written by v2 pack for empty dirs)
        const bool is_dir_entry = (!rel.empty() && rel.back() == '/');
        const std::string rel_path = is_dir_entry ? rel.substr(0, rel.size() - 1) : rel;

        // Security check: reject directory traversal
        if (rel_path.find("..") != std::string::npos
            || (!rel_path.empty() && (rel_path[0] == '/' || rel_path[0] == '\\'))) {
            throw CryptoException(ErrorCode::CORRUPTED_FILE,
                "archive contains forbidden path traversal: " + rel);
        }

        uint64_t file_size = read_u64_le(in);
        bytes_read += 2 + path_len + 8;

        // Directory entries are flagged by a trailing slash and must have no payload.
        if (is_dir_entry) {
            if (file_size != 0) {
                throw CryptoException(ErrorCode::CORRUPTED_FILE,
                    "directory entry has non-zero size: " + rel);
            }
            fs::path full_dest = target_base / rel_path;
            fs::create_directories(full_dest, ec);
            if (ec) {
                throw CryptoException(ErrorCode::PERMISSION_DENIED,
                    "cannot create directory: " + full_dest.string());
            }
            if (progress) progress(bytes_read);
            continue;
        }

        // Handle file entry
        fs::path full_dest = target_base / rel_path;
        fs::create_directories(full_dest.parent_path(), ec);
        if (ec) {
            throw CryptoException(ErrorCode::PERMISSION_DENIED,
                "cannot create directory: " + full_dest.parent_path().string());
        }

        std::ofstream out_file(full_dest, std::ios::binary);
        if (!out_file) {
            throw CryptoException(ErrorCode::PERMISSION_DENIED,
                "cannot create file: " + full_dest.string());
        }

        uint64_t remaining = file_size;
        while (remaining > 0) {
            size_t chunk = static_cast<size_t>(std::min<uint64_t>(remaining, copy_buf.size()));
            in.read(copy_buf.data(), static_cast<std::streamsize>(chunk));
            std::streamsize got = in.gcount();
            if (got <= 0) {
                throw CryptoException(ErrorCode::CORRUPTED_FILE,
                    "archive truncated while reading: " + rel_path);
            }
            out_file.write(copy_buf.data(), got);
            if (!out_file) {
                throw CryptoException(ErrorCode::IO_ERROR,
                    "write error: " + full_dest.string());
            }

            remaining -= static_cast<uint64_t>(got);
            bytes_read += static_cast<uint64_t>(got);
            if (progress) progress(bytes_read);
        }
        out_file.flush();
    }
}

// ── High-level wrappers ───────────────────────────────────────────────────────

void encrypt_directory(
    const std::string& dir_path,
    const std::string& output_path,
    const SecureString& password,
    const EncryptParams& params)
{
    std::string tmp_archive = output_path + ".archive_tmp";

    try {
        pack_directory(dir_path, tmp_archive, params.progress_callback);
        encrypt_file(tmp_archive, output_path, password, params);
        secure_delete(tmp_archive);
    } catch (...) {
        secure_delete(tmp_archive);
        throw;
    }
}

void decrypt_directory(
    const std::string& input_path,
    const std::string& out_dir,
    const SecureString& password,
    const DecryptParams& params)
{
    std::string tmp_archive = input_path + ".archive_tmp";

    try {
        decrypt_file(input_path, tmp_archive, password, params);
        unpack_directory(tmp_archive, out_dir, params.progress_callback);
        std::error_code ec;
        fs::remove(tmp_archive, ec);
    } catch (...) {
        std::error_code ec;
        fs::remove(tmp_archive, ec);
        throw;
    }
}

} // namespace minicrypto
