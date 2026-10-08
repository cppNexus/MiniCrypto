#include "../core/file_ops.h"
#include "../core/format.h"
#include "../core/crypto.h"
#include "../core/secure_memory.h"
#include <sodium.h>
#include <filesystem>
#include <cstdio>
#include <cstring>
#include <vector>
#include <iostream>
#include <algorithm>

#ifdef _WIN32
#include <io.h>
#define portable_fileno _fileno
#define portable_fsync _commit
#else
#include <unistd.h>
#define portable_fileno fileno
#define portable_fsync fsync
#endif

namespace minicrypto {

// ── AtomicFile ────────────────────────────────────────────────────────────────

AtomicFile::AtomicFile(const std::string& path)
    : final_path_(path), temp_path_(path + ".tmp"), committed_(false)
{
    stream_.open(temp_path_, std::ios::binary);
    if (!stream_) {
        throw CryptoException(ErrorCode::PERMISSION_DENIED,
            "cannot create temp file: " + temp_path_);
    }
}

AtomicFile::~AtomicFile() {
    if (!committed_) {
        stream_.close();
        std::error_code ec;
        std::filesystem::remove(temp_path_, ec);
    }
}

void AtomicFile::commit() {
    stream_.flush();
    if (!stream_) {
        throw CryptoException(ErrorCode::IO_ERROR, "flush failed before commit");
    }
    stream_.close();

    std::error_code ec;
    std::filesystem::rename(temp_path_, final_path_, ec);
    if (ec) {
        // On Windows, if destination exists, rename may fail unless removed first
        std::filesystem::remove(final_path_, ec);
        std::filesystem::rename(temp_path_, final_path_, ec);
        if (ec) {
            throw CryptoException(ErrorCode::PERMISSION_DENIED,
                "cannot finalize file: " + final_path_ + " (" + ec.message() + ")");
        }
    }

    committed_ = true;
}

// ── secure_delete ─────────────────────────────────────────────────────────────

void secure_delete(const std::string& path) {
    std::ifstream test(path, std::ios::binary);
    if (!test) return;

    test.seekg(0, std::ios::end);
    size_t fsize = static_cast<size_t>(test.tellg());
    test.close();

    std::cout << "Shredding " << path << "... " << std::flush;

    FILE* fp = std::fopen(path.c_str(), "r+b");
    if (!fp) {
        core_warn("secure_delete: cannot open file for shredding: " + path);
        return;
    }

    int fd = portable_fileno(fp);
    std::vector<unsigned char> noise(CHUNK_SIZE);

    // 3-pass overwrite: 0xFF, 0x00, random
    for (int pass = 0; pass < 3; ++pass) {
        std::fseek(fp, 0, SEEK_SET);

        for (size_t written = 0; written < fsize; written += CHUNK_SIZE) {
            size_t chunk = std::min(CHUNK_SIZE, fsize - written);

            if (pass == 0) {
                std::memset(noise.data(), 0xFF, chunk);
            } else if (pass == 1) {
                std::memset(noise.data(), 0x00, chunk);
            } else {
                randombytes_buf(noise.data(), chunk);
            }

            std::fwrite(noise.data(), 1, chunk, fp);
        }

        std::fflush(fp);
        if (portable_fsync(fd) != 0) {
            core_warn("fsync failed — data may not be committed to disk");
        }
    }

    std::fclose(fp);

    std::error_code ec;
    if (std::filesystem::remove(path, ec)) {
        std::cout << "[OK]\n";
    } else {
        std::cout << "[WARNING] (couldn't unlink)\n";
    }

    std::cout << "Note: secure_delete is best-effort "
                 "(SSD/CoW filesystems may retain copies)\n";
}

} // namespace minicrypto