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

static bool is_terminal_input() {
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

// Disable/enable terminal echo for password input
static void set_echo(bool enable) {
    if (!is_terminal_input()) return;

#ifdef _WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    if (hStdin == INVALID_HANDLE_VALUE) return;
    DWORD mode = 0;
    if (GetConsoleMode(hStdin, &mode)) {
        if (enable) {
            mode |= ENABLE_ECHO_INPUT;
        } else {
            mode &= ~ENABLE_ECHO_INPUT;
        }
        SetConsoleMode(hStdin, mode);
    }
#else
    struct termios tty;
    if (tcgetattr(STDIN_FILENO, &tty) == 0) {
        if (enable) {
            tty.c_lflag |= ECHO;
        } else {
            tty.c_lflag &= ~ECHO;
        }
        tcsetattr(STDIN_FILENO, TCSANOW, &tty);
    }
#endif
}

SecureString get_password_interactive(bool confirm) {
    bool is_interactive = is_terminal_input();

    if (is_interactive) {
        std::cout << "Enter password: " << std::flush;
        set_echo(false);
    }

    std::string password1;
    if (!std::getline(std::cin, password1)) {
        if (is_interactive) set_echo(true);
        throw CryptoException(ErrorCode::AUTH_FAILED, "failed to read password from input");
    }

    // Strip trailing \r (CRLF endings on Windows or raw streams)
    if (!password1.empty() && password1.back() == '\r') {
        password1.pop_back();
    }

    if (is_interactive) {
        std::cout << std::endl;
    }

    if (confirm) {
        if (is_interactive) {
            std::cout << "Confirm password: " << std::flush;
            std::string password2;
            std::getline(std::cin, password2);
            std::cout << std::endl;
            set_echo(true);

            if (!password2.empty() && password2.back() == '\r') {
                password2.pop_back();
            }

            if (password1 != password2) {
                sodium_memzero(&password1[0], password1.size());
                sodium_memzero(&password2[0], password2.size());
                throw CryptoException(ErrorCode::AUTH_FAILED, "passwords do not match");
            }
        }
        // In non-interactive mode (pipes, automation), no confirmation prompt is requested.
    } else if (is_interactive) {
        set_echo(true);
    }

    SecureString result(password1.c_str(), password1.size());
    sodium_memzero(&password1[0], password1.size());
    return result;
}

void warn(const std::string& msg) {
    std::cerr << colorize("[WARNING]", TerminalColor::YELLOW, true)
              << " " << msg << std::endl;
}

} // namespace minicrypto