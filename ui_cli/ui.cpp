#include "ui.h"
#include "../core/crypto.h"
#include <iostream>
#include <iomanip>
#include <cstring>
#include <sodium.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <io.h>
#define portable_isatty _isatty
#define portable_fileno _fileno
#else
#include <termios.h>
#include <unistd.h>
#define portable_isatty isatty
#define portable_fileno fileno
#endif

namespace minicrypto {

static bool is_terminal_output() {
#ifdef _WIN32
    return (portable_isatty(portable_fileno(stdout)) != 0);
#else
    return (isatty(STDOUT_FILENO) != 0);
#endif
}

static bool is_terminal_error() {
#ifdef _WIN32
    return (portable_isatty(portable_fileno(stderr)) != 0);
#else
    return (isatty(STDERR_FILENO) != 0);
#endif
}

std::string colorize(const std::string& text, TerminalColor color, bool stderr_stream) {
    if (stderr_stream ? !is_terminal_error() : !is_terminal_output()) return text;

    const char* code = "";
    switch (color) {
    case TerminalColor::GREEN:  code = "\033[32m"; break;
    case TerminalColor::RED:    code = "\033[31m"; break;
    case TerminalColor::YELLOW: code = "\033[33m"; break;
    }
    return std::string(code) + text + "\033[0m";
}

bool is_terminal_input() {
#ifdef _WIN32
    return (portable_isatty(portable_fileno(stdin)) != 0);
#else
    return (isatty(STDIN_FILENO) != 0);
#endif
}

ProgressBar::ProgressBar(uint64_t total)
    : total_(total), current_(0), last_percent_(-1) {
    if (total_ > 0 && is_terminal_output()) {
        std::cout << "Progress: 0%" << std::flush;
    }
}

void ProgressBar::update(uint64_t current) {
    current_ = current;

    if (total_ == 0 || !is_terminal_output()) return;

    int percent = static_cast<int>((current_ * 100) / total_);
    if (percent != last_percent_) {
        std::cout << "\rProgress: " << percent << "%" << std::flush;
        last_percent_ = percent;
    }
}

void ProgressBar::finish() {
    if (total_ > 0 && is_terminal_output()) {
        std::cout << "\rProgress: 100%" << std::endl;
    }
}

class TerminalEchoGuard {
    bool active_ = false;
#ifdef _WIN32
    HANDLE handle_ = INVALID_HANDLE_VALUE;
    DWORD original_mode_ = 0;
#else
    struct termios original_mode_{};
#endif
public:
    TerminalEchoGuard() {
        if (!is_terminal_input()) return;
#ifdef _WIN32
        handle_ = GetStdHandle(STD_INPUT_HANDLE);
        if (handle_ == INVALID_HANDLE_VALUE || !GetConsoleMode(handle_, &original_mode_)) {
            throw CryptoException(ErrorCode::IO_ERROR,
                "cannot read terminal mode; refusing to read password");
        }
        if (!SetConsoleMode(handle_, original_mode_ & ~ENABLE_ECHO_INPUT)) {
            throw CryptoException(ErrorCode::IO_ERROR,
                "cannot disable terminal echo; refusing to read password");
        }
#else
        if (tcgetattr(STDIN_FILENO, &original_mode_) != 0) {
            throw CryptoException(ErrorCode::IO_ERROR,
                "cannot read terminal mode; refusing to read password");
        }
        struct termios hidden_mode = original_mode_;
        hidden_mode.c_lflag &= static_cast<tcflag_t>(~ECHO);
        if (tcsetattr(STDIN_FILENO, TCSANOW, &hidden_mode) != 0) {
            throw CryptoException(ErrorCode::IO_ERROR,
                "cannot disable terminal echo; refusing to read password");
        }
#endif
        active_ = true;
    }

    bool restore() noexcept {
        if (!active_) return true;
#ifdef _WIN32
        const bool restored = SetConsoleMode(handle_, original_mode_) != 0;
#else
        const bool restored = tcsetattr(STDIN_FILENO, TCSANOW, &original_mode_) == 0;
#endif
        if (restored) active_ = false;
        return restored;
    }

    ~TerminalEchoGuard() {
        (void)restore();
    }

    TerminalEchoGuard(const TerminalEchoGuard&) = delete;
    TerminalEchoGuard& operator=(const TerminalEchoGuard&) = delete;
};

class StringWiper {
    std::string& value_;
public:
    explicit StringWiper(std::string& value) : value_(value) {}
    ~StringWiper() {
        if (!value_.empty()) sodium_memzero(value_.data(), value_.size());
    }
    StringWiper(const StringWiper&) = delete;
    StringWiper& operator=(const StringWiper&) = delete;
};

static std::string read_password_line(const std::string& prompt, bool interactive) {
    if (interactive) std::cout << prompt << std::flush;
    std::string value;
    {
        TerminalEchoGuard echo_guard;
        if (!std::getline(std::cin, value)) {
            if (!value.empty()) sodium_memzero(value.data(), value.size());
            throw CryptoException(ErrorCode::AUTH_FAILED,
                "failed to read password from input");
        }
        if (!echo_guard.restore()) {
            if (!value.empty()) sodium_memzero(value.data(), value.size());
            throw CryptoException(ErrorCode::IO_ERROR,
                "failed to restore terminal mode after password input");
        }
    }
    if (!value.empty() && value.back() == '\r') value.pop_back();
    if (interactive) std::cout << std::endl;
    return value;
}

SecureString get_password_interactive(bool confirm) {
    return get_password_interactive(confirm, "password");
}

SecureString get_password_interactive(bool confirm, const std::string& label) {
    bool is_interactive = is_terminal_input();
    std::string password1 = read_password_line("Enter " + label + ": ", is_interactive);
    StringWiper wipe_password1(password1);

    if (confirm) {
        if (is_interactive) {
            std::string password2 = read_password_line(
                "Confirm " + label + ": ", is_interactive);
            StringWiper wipe_password2(password2);

            if (password1.size() != password2.size() ||
                sodium_memcmp(password1.data(), password2.data(), password1.size()) != 0) {
                throw CryptoException(ErrorCode::AUTH_FAILED, "passwords do not match");
            }
        }
        // In non-interactive mode (pipes, automation), no confirmation prompt is requested.
    }

    SecureString result(password1.c_str(), password1.size());
    return result;
}

std::string get_optional_path_interactive(const std::string& prompt) {
    if (!is_terminal_input()) {
        throw CryptoException(ErrorCode::INVALID_MODE,
            "this prompt requires an interactive terminal");
    }
    std::cout << prompt << std::flush;
    std::string value;
    {
        TerminalEchoGuard echo_guard;
        if (!std::getline(std::cin, value)) {
            if (!value.empty()) sodium_memzero(value.data(), value.size());
            throw CryptoException(ErrorCode::IO_ERROR, "failed to read interactive input");
        }
        if (!echo_guard.restore()) {
            if (!value.empty()) sodium_memzero(value.data(), value.size());
            throw CryptoException(ErrorCode::IO_ERROR,
                "failed to restore terminal mode after interactive input");
        }
    }
    if (!value.empty() && value.back() == '\r') value.pop_back();
    std::cout << std::endl;
    return value;
}

void warn(const std::string& msg) {
    std::cerr << colorize("[WARNING]", TerminalColor::YELLOW, true)
              << " " << msg << std::endl;
}

} // namespace minicrypto