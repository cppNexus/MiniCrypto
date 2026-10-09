#ifndef MINICRYPTO_FILE_OPS_H
#define MINICRYPTO_FILE_OPS_H

#include <fstream>
#include <filesystem>

namespace minicrypto {

// Atomic file writer (write to .tmp, then rename)
class AtomicFile {
    std::filesystem::path final_path_;
    std::filesystem::path temp_path_;
    std::ofstream stream_;
    bool committed_;

public:
    explicit AtomicFile(const std::filesystem::path& path);
    ~AtomicFile();

    std::ofstream& get() { return stream_; }
    void commit();

    AtomicFile(const AtomicFile&) = delete;
    AtomicFile& operator=(const AtomicFile&) = delete;
};

// Secure file deletion (3-pass overwrite + fsync)
// WARNING: Best-effort only on SSD/CoW filesystems
void secure_delete(const std::filesystem::path& path);

} // namespace minicrypto

#endif // MINICRYPTO_FILE_OPS_H