#ifndef MINICRYPTO_SECURE_MEMORY_H
#define MINICRYPTO_SECURE_MEMORY_H

#include <cstddef>
#include <string>
#include <vector>
#include <sodium.h>

namespace minicrypto {

/// Lightweight internal warning: writes to stderr, no UI dependency.
void core_warn(const std::string& msg);

void secure_zero(void* ptr, size_t size);

/// RAII memory zeroing guard for arbitrary memory buffers
struct BufferZeroGuard {
    void* ptr = nullptr;
    size_t size = 0;

    BufferZeroGuard(void* p, size_t s) noexcept : ptr(p), size(s) {}
    ~BufferZeroGuard() {
        if (ptr && size > 0) {
            sodium_memzero(ptr, size);
        }
    }

    BufferZeroGuard(const BufferZeroGuard&) = delete;
    BufferZeroGuard& operator=(const BufferZeroGuard&) = delete;
    BufferZeroGuard(BufferZeroGuard&&) = delete;
    BufferZeroGuard& operator=(BufferZeroGuard&&) = delete;
};

class SecureBuffer {
    unsigned char* data_ = nullptr;
    size_t size_ = 0;
    bool mlocked_ = false;

public:
    explicit SecureBuffer(size_t n);
    ~SecureBuffer();

    unsigned char* data() noexcept { return data_; }
    const unsigned char* data() const noexcept { return data_; }
    size_t size() const noexcept { return size_; }

    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;
    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;
};

class SecureString {
    std::vector<char> data_;
    bool mlocked_ = false;

public:
    SecureString() = default;
    explicit SecureString(const char* str, size_t len);
    ~SecureString();

    const char* c_str() const noexcept { return data_.empty() ? "" : data_.data(); }
    const char* data() const noexcept { return data_.empty() ? "" : data_.data(); }
    size_t size() const noexcept { return data_.empty() ? 0 : data_.size() - 1; }
    bool empty() const noexcept { return data_.empty() || data_[0] == '\0'; }

    SecureString(const SecureString&) = delete;
    SecureString& operator=(const SecureString&) = delete;
    SecureString(SecureString&& other) noexcept;
    SecureString& operator=(SecureString&& other) noexcept;
};

} // namespace minicrypto

#endif // MINICRYPTO_SECURE_MEMORY_H