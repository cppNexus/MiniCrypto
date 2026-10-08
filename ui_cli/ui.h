#ifndef MINICRYPTO_UI_H
#define MINICRYPTO_UI_H

#include "../core/secure_memory.h"
#include <string>
#include <cstdint>

namespace minicrypto {

// Progress bar for encryption/decryption
class ProgressBar {
    uint64_t total_;
    uint64_t current_;
    int last_percent_;
    
public:
    explicit ProgressBar(uint64_t total);
    void update(uint64_t current);
    void finish();
};

// Get password from terminal (secure input)
SecureString get_password_interactive(bool confirm);

// Warning message
void warn(const std::string& msg);

} // namespace minicrypto

#endif // MINICRYPTO_UI_H