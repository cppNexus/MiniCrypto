cmake_minimum_required(VERSION 3.15)
project(minicrypto VERSION 2.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Build options
option(BUILD_SHARED_LIBS "Build shared library" OFF)
option(BUILD_CLI "Build CLI executable" ON)
option(BUILD_STATIC_CLI "Build statically linked CLI" OFF)
option(BUILD_TESTS "Build test suite" ON)

# Compiler & Security flags (cross-platform)
if(MSVC)
    add_compile_options(/W4 /permissive-)
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        add_compile_options(/O2)
    endif()
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -fPIC")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector-strong")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -march=native")
endif()

# === CORE LIBRARY (no UI dependencies) ===
set(CORE_SOURCES
    core/crypto.cpp
    core/deniable.cpp
    core/keygen.cpp
    core/format.cpp
    core/secure_memory.cpp
    core/file_ops.cpp
    core/dir_ops.cpp
)

set(CORE_HEADERS
    core/crypto.h
    core/deniable.h
    core/keygen.h
    core/format.h
    core/secure_memory.h
    core/file_ops.h
    core/dir_ops.h
)

# Find required libraries
find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(SODIUM QUIET libsodium)
    pkg_check_modules(ARGON2 QUIET libargon2)
endif()

# Fallback for platforms where pkg-config or one of the .pc modules is absent
# (e.g. some Windows/vcpkg and macOS package-manager configurations).
if(NOT SODIUM_FOUND)
    find_path(SODIUM_INCLUDE_DIRS NAMES sodium.h PATH_SUFFIXES sodium)
    find_library(SODIUM_LIBRARY NAMES sodium libsodium)
    if(NOT SODIUM_INCLUDE_DIRS OR NOT SODIUM_LIBRARY)
        message(FATAL_ERROR "libsodium headers and library are required")
    endif()
    set(SODIUM_LIBRARIES ${SODIUM_LIBRARY})
endif()

if(NOT ARGON2_FOUND)
    find_path(ARGON2_INCLUDE_DIRS NAMES argon2.h)
    find_library(ARGON2_LIBRARY NAMES argon2 libargon2)
    if(NOT ARGON2_INCLUDE_DIRS OR NOT ARGON2_LIBRARY)
        message(FATAL_ERROR "libargon2 headers and library are required")
    endif()
    set(ARGON2_LIBRARIES ${ARGON2_LIBRARY})
endif()

# Core library
add_library(minicrypto_core ${CORE_SOURCES})
target_include_directories(minicrypto_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:include>
        ${SODIUM_INCLUDE_DIRS}
        ${ARGON2_INCLUDE_DIRS}
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/core
)

target_link_libraries(minicrypto_core
    PUBLIC
        ${SODIUM_LIBRARIES}
        ${ARGON2_LIBRARIES}
)

if(WIN32)
    target_link_libraries(minicrypto_core PUBLIC ws2_32 advapi32)
endif()

if(SODIUM_LIBRARY_DIRS OR ARGON2_LIBRARY_DIRS)
    target_link_directories(minicrypto_core
        PUBLIC
            ${SODIUM_LIBRARY_DIRS}
            ${ARGON2_LIBRARY_DIRS}
    )
endif()

# Set library properties
set_target_properties(minicrypto_core PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 2
    PUBLIC_HEADER "${CORE_HEADERS}"
)

# === CLI APPLICATION ===
if(BUILD_CLI)
    set(CLI_SOURCES
        ui_cli/main.cpp
        ui_cli/ui.cpp
    )

    set(CLI_HEADERS
        ui_cli/ui.h
    )

    if(BUILD_STATIC_CLI)
        # Request static linking where the target toolchain and dependencies support it.
        # This option does not guarantee a fully static binary on every platform.
        add_executable(minicrypto ${CLI_SOURCES})
        if(MSVC)
            set_property(TARGET minicrypto PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
            target_link_libraries(minicrypto
                PRIVATE
                    minicrypto_core
            )
        else()
            target_link_libraries(minicrypto
                PRIVATE
                    minicrypto_core
                    -static
            )
            set_target_properties(minicrypto PROPERTIES
                LINK_FLAGS "-static -s"
                LINK_SEARCH_START_STATIC ON
                LINK_SEARCH_END_STATIC ON
            )
        endif()
    else()
        # Regular dynamic CLI
        add_executable(minicrypto ${CLI_SOURCES})
        target_link_libraries(minicrypto
            PRIVATE
                minicrypto_core
        )
    endif()

    target_include_directories(minicrypto
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}
    )
endif()

# === TESTS ===
if(BUILD_TESTS)
    enable_testing()
    add_executable(minicrypto_tests tests/test_main.cpp)
    target_link_libraries(minicrypto_tests
        PRIVATE
            minicrypto_core
    )
    target_include_directories(minicrypto_tests
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}
    )
    add_test(NAME AllTests COMMAND minicrypto_tests)
endif()

# === INSTALLATION ===
include(GNUInstallDirs)

# Install library
install(TARGETS minicrypto_core
    EXPORT minicryptoTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/minicrypto/core
)

# Install CLI
if(BUILD_CLI)
    install(TARGETS minicrypto
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
endif()

# Install cmake config
install(EXPORT minicryptoTargets
    FILE minicryptoTargets.cmake
    NAMESPACE minicrypto::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/minicrypto
)

# === PACKAGING ===
set(CPACK_PACKAGE_NAME "minicrypto")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Secure file and directory encryption library")
set(CPACK_PACKAGE_VENDOR "MiniCrypto")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")

include(CPack)