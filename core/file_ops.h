#ifndef MINICRYPTO_FILE_OPS_H
#define MINICRYPTO_FILE_OPS_H

#include <string>
#include <fstream>

namespace minicrypto {

// Atomic file writer (write to .tmp, then rename)
class AtomicFile {
    std::string final_path_;
    std::string temp_path_;
    std::ofstream stream_;
    bool committed_;
    
public:
    explicit AtomicFile(const std::string& path);
    ~AtomicFile();
    
    std::ofstream& get() { return stream_; }
    void commit();
    
    AtomicFile(const AtomicFile&) = delete;
    AtomicFile& operator=(const AtomicFile&) = delete;
};

// Secure file deletion (3-pass overwrite + fsync)
// WARNING: Best-effort only on SSD/CoW filesystems
void secure_delete(const std::string& path);

} // namespace minicrypto

#endif // MINICRYPTO_FILE_OPS_H