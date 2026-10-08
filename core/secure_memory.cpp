#include "../core/secure_memory.h"
#include <sodium.h>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <utility>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <memoryapi.h>
#else
#include <sys/mman.h>
#endif

namespace minicrypto {

void core_warn(const std::string& msg) {
    std::cerr << "warning: " << msg << "\n";
}

void secure_zero(void* ptr, size_t size) {
    sodium_memzero(ptr, size);
}

// ── SecureBuffer ──────────────────────────────────────────────────────────────

SecureBuffer::SecureBuffer(size_t n) : size_(n), mlocked_(false) {
    data_ = static_cast<unsigned char*>(sodium_malloc(n));
    if (!data_) {
        throw std::bad_alloc();
    }

#ifdef _WIN32
    if (!VirtualLock(data_, n)) {
        core_warn("VirtualLock failed — memory may be swapped to disk");
    } else {
        mlocked_ = true;
    }
#else
    if (mlock(data_, n) != 0) {
        core_warn("mlock failed — memory may be swapped to disk (CAP_IPC_LOCK missing?)");
    } else {
        mlocked_ = true;
    }
#endif
}

SecureBuffer::~SecureBuffer() {
    if (data_) {
        sodium_memzero(data_, size_);
        if (mlocked_) {
#ifdef _WIN32
            VirtualUnlock(data_, size_);
#else
            munlock(data_, size_);
#endif
        }
        sodium_free(data_);
        data_ = nullptr;
    }
}

SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept
    : data_(other.data_), size_(other.size_), mlocked_(other.mlocked_) {
    other.data_ = nullptr;
    other.size_ = 0;
    other.mlocked_ = false;
}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
        if (data_) {
            sodium_memzero(data_, size_);
            if (mlocked_) {
#ifdef _WIN32
                VirtualUnlock(data_, size_);
#else
                munlock(data_, size_);
#endif
            }
            sodium_free(data_);
        }
        data_ = other.data_;
        size_ = other.size_;
        mlocked_ = other.mlocked_;
        other.data_ = nullptr;
        other.size_ = 0;
        other.mlocked_ = false;
    }
    return *this;
}

// ── SecureString ──────────────────────────────────────────────────────────────

SecureString::SecureString(const char* str, size_t len) : mlocked_(false) {
    data_.resize(len + 1);

#ifdef _WIN32
    if (!VirtualLock(data_.data(), data_.size())) {
        core_warn("password VirtualLock failed — password may be swapped to disk");
    } else {
        mlocked_ = true;
    }
#else
    if (mlock(data_.data(), data_.size()) != 0) {
        core_warn("password mlock failed — password may be swapped to disk");
    } else {
        mlocked_ = true;
    }
#endif

    std::memcpy(data_.data(), str, len);
    data_[len] = '\0';
}

SecureString::~SecureString() {
    if (!data_.empty()) {
        sodium_memzero(data_.data(), data_.size());
        if (mlocked_) {
#ifdef _WIN32
            VirtualUnlock(data_.data(), data_.size());
#else
            munlock(data_.data(), data_.size());
#endif
        }
    }
}

SecureString::SecureString(SecureString&& other) noexcept
    : data_(std::move(other.data_)), mlocked_(other.mlocked_) {
    other.mlocked_ = false;
}

SecureString& SecureString::operator=(SecureString&& other) noexcept {
    if (this != &other) {
        if (!data_.empty()) {
            sodium_memzero(data_.data(), data_.size());
            if (mlocked_) {
#ifdef _WIN32
                VirtualUnlock(data_.data(), data_.size());
#else
                munlock(data_.data(), data_.size());
#endif
            }
        }

        data_         = std::move(other.data_);
        mlocked_      = other.mlocked_;
        other.mlocked_ = false;
    }
    return *this;
}

} // namespace minicrypto