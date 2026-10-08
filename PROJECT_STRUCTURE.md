# MiniCrypto Complete Project Structure

## Directory Layout

```
minicrypto/
├── CMakeLists.txt
├── README.md
├── FAQ.md
├── DETERMINISTIC_WARN.txt
├── LICENSE
│
├── core/                       # Core library (no UI dependencies)
│   ├── crypto.cpp
│   ├── crypto.h
│   ├── dir_ops.cpp             # Directory archiving & recursive encryption
│   ├── dir_ops.h
│   ├── keygen.cpp
│   ├── keygen.h
│   ├── format.cpp
│   ├── format.h
│   ├── secure_memory.cpp
│   ├── secure_memory.h
│   ├── file_ops.cpp
│   └── file_ops.h
│
├── ui_cli/                     # CLI interface
│   ├── main.cpp
│   ├── ui.cpp
│   └── ui.h
│
├── docs/                       # Documentation
│   ├── SECURITY.md
│   ├── ARCHITECTURE.md
│   └── IMPLEMENTATION_SUMMARY.md
│
├── tests/                      # Tests (optional)
│   └── test_main.cpp
│
└── .github/                    # CI/CD
    └── workflows/
        └── security-audit.yml
```

## Build Instructions

### 1. Install Dependencies

```bash
# Ubuntu/Debian
sudo apt-get install libsodium-dev libargon2-dev cmake build-essential

# Fedora/RHEL
sudo dnf install libsodium-devel libargon2-devel cmake gcc-c++

# Arch Linux
sudo pacman -S libsodium argon2 cmake base-devel
```

### 2. Build Dynamic CLI

```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
sudo make install
```

### 3. Build Static CLI (Air-Gapped)

```bash
mkdir build-static && cd build-static
cmake .. -DBUILD_STATIC_CLI=ON
make -j$(nproc)
# Binary: ./minicrypto (fully static)
```

### 4. Build Library Only

```bash
mkdir build-lib && cd build-lib
cmake .. -DBUILD_CLI=OFF
make -j$(nproc)
sudo make install
# Installs: libminicrypto_core.so + headers
```

## File Contents Check

### Required Files

All these files must exist and be compilable:

```bash
# Core library
[v] core/crypto.cpp          # Encryption/decryption implementation
[v] core/crypto.h            # Public API
[v] core/keygen.cpp          # Key derivation functions
[v] core/keygen.h            # KDF declarations
[v] core/format.cpp          # Format validation
[v] core/format.h            # File format structures
[v] core/secure_memory.cpp   # Memory management
[v] core/secure_memory.h     # SecureBuffer/SecureString
[v] core/file_ops.cpp        # Atomic writes, secure delete
[v] core/file_ops.h          # File operations

# CLI
[v] ui_cli/main.cpp          # CLI entry point
[v] ui_cli/ui.cpp            # Progress bars, prompts
[v] ui_cli/ui.h              # UI declarations

# Build system
[v] CMakeLists.txt           # Build configuration

# Documentation
[v] README.md                # Quick start
[v] FAQ.md                   # User questions
[v] DETERMINISTIC_WARN.txt   # Security warning
[v] docs/SECURITY.md         # Security analysis
[v] docs/ARCHITECTURE.md     # Design decisions

# CI/CD
[v] .github/workflows/security-audit.yml  # Automated checks
```

## Compilation Dependencies

### Include Paths

Files must use correct relative includes:

```cpp
// In core/*.cpp files:
#include "crypto.h"        // NOT "../core/crypto.h"
#include "keygen.h"
#include "format.h"

// In ui_cli/*.cpp files:
#include "../core/crypto.h"  // Correct: go up one level
#include "../ui_cli/ui.h"    // Correct: same directory via ..
```

### Link Order

CMake must link in correct order:

```cmake
# Core library (no dependencies on ui_cli)
add_library(minicrypto_core ${CORE_SOURCES})
target_link_libraries(minicrypto_core PRIVATE ${SODIUM_LIBRARIES} ${ARGON2_LIBRARIES})

# CLI (depends on core)
add_executable(minicrypto ${CLI_SOURCES})
target_link_libraries(minicrypto PRIVATE minicrypto_core)
```

## Common Build Errors

### Error 1: "No declaration of derive_deterministic_prekey"

**Cause**: Missing `#include "keygen.h"` in `crypto.cpp`

**Fix**: 
```cpp
// In core/crypto.cpp
#include "keygen.h"  // Add this line
```

### Error 2: "cannot find -lsodium"

**Cause**: libsodium not installed

**Fix**:
```bash
sudo apt-get install libsodium-dev
```

### Error 3: "undefined reference to crypto_secretstream_*"

**Cause**: Not linking libsodium

**Fix**: Check CMakeLists.txt has:
```cmake
target_link_libraries(minicrypto_core PRIVATE ${SODIUM_LIBRARIES})
```

### Error 4: "../core/crypto.h: No such file"

**Cause**: Wrong include path

**Fix**: Use relative includes as shown above

## Verification

After successful build, verify:

```bash
# 1. Binary exists
ls -lh build/minicrypto

# 2. Dynamic dependencies (dynamic build)
ldd build/minicrypto
# Should show: libsodium.so, libargon2.so, libc.so

# 3. Static dependencies (static build)
ldd build-static/minicrypto
# Should say: "not a dynamic executable"

# 4. Test run
./build/minicrypto test
# Should output: "[PASS] All tests passed!"

# 5. Encrypt test
echo "test" > test.txt
./build/minicrypto lock test.txt
# Should create test.txt.mcc

# 6. Decrypt test
./build/minicrypto unlock test.txt.mcc
# Should create test.txt (decrypted)
```

## CI Verification

GitHub Actions will automatically check:

- [v] Code compiles without warnings
- [v] Static binary has no network symbols
- [v] No telemetry code
- [v] All tests pass
- [v] Documentation is complete
- [v] Format versioning is correct

## Install Verification

After `sudo make install`:

```bash
# 1. Binary installed
which minicrypto
# Should output: /usr/local/bin/minicrypto

# 2. Headers installed
ls /usr/local/include/minicrypto/core/
# Should list: crypto.h, keygen.h, format.h, etc.

# 3. Library installed
ls /usr/local/lib/libminicrypto_core.*
# Should show: .so or .a file

# 4. Test from any directory
cd /tmp
minicrypto test
# Should work
```