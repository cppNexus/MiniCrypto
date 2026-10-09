#ifndef MINICRYPTO_FILE_OPS_H
#define MINICRYPTO_FILE_OPS_H

#include <fstream>
#include <filesystem>

namespace minicrypto {

// Temporary-file writer followed by rename. Platform/failure-mode limitations
// apply; this is not a universal guarantee that an existing target is preserved.
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

// Best-effort file overwrite (multiple passes) and unlink. Physical erasure is
// not guaranteed; errors and filesystem/device behavior can leave recoverable data.
void secure_delete(const std::filesystem::path& path);

} // namespace minicrypto

#endif // MINICRYPTO_FILE_OPS_H