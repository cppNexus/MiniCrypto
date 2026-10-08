#include "format.h"

namespace minicrypto {

HeaderStatus validate_header(const Header& h) {
    // Check magic number
    if (h.magic != MAGIC) {
        return HeaderStatus::INVALID_MAGIC;
    }
    
    // Check version support
    if (h.version < VERSION_MIN_SUPPORTED) {
        return HeaderStatus::UNSUPPORTED_VERSION;
    }
    
    if (h.version > VERSION_CURRENT) {
        // File is from newer version
        return HeaderStatus::UNSUPPORTED_VERSION;
    }
    
    // Basic sanity checks
    if (h.argon_time == 0 || h.argon_time > 100) {
        return HeaderStatus::CORRUPTED;
    }
    
    if (h.argon_mem_kb < 8 || h.argon_mem_kb > (10 * 1024 * 1024)) {  // 8KB to 10GB
        return HeaderStatus::CORRUPTED;
    }
    
    if (h.argon_threads == 0 || h.argon_threads > 256) {
        return HeaderStatus::CORRUPTED;
    }
    
    // Mode validation
    if (h.mode > 3) {  // EncryptionMode enum has 4 values (0-3)
        return HeaderStatus::CORRUPTED;
    }
    
    return HeaderStatus::VALID;
}

const char* header_status_string(HeaderStatus status) {
    switch (status) {
    case HeaderStatus::VALID:
        return "valid";
    case HeaderStatus::INVALID_MAGIC:
        return "invalid magic number (not a MiniCrypto file or corrupted)";
    case HeaderStatus::UNSUPPORTED_VERSION:
        return "unsupported version (file too old or created with newer software)";
    case HeaderStatus::CORRUPTED:
        return "corrupted header (invalid parameters)";
    default:
        return "unknown error";
    }
}

} // namespace minicrypto