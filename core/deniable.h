#ifndef MINICRYPTO_DENIABLE_H
#define MINICRYPTO_DENIABLE_H

#include "secure_memory.h"
#include <cstdint>
#include <filesystem>

namespace minicrypto {

// Experimental two-slot container parameters. Values are deliberately not
// serialized; both sides must use the same KDF settings. The CLI uses defaults.
struct DeniableContainerOptions {
    uint64_t slot_size_bytes = 16ULL * 1024ULL * 1024ULL;
    uint32_t argon_time = 3;
    uint32_t argon_mem_kb = 1U << 17;
    uint32_t argon_threads = 2;
};

// Creates two equal-sized slots: a password-protected cover slot and either a
// password-protected hidden slot or indistinguishable-length random filler.
// hidden_input and hidden_password must either both be null or both be present.
// This format is experimental and is not resistant to multi-snapshot analysis.
void create_deniable_container(
    const std::filesystem::path& cover_input,
    const std::filesystem::path* hidden_input,
    const std::filesystem::path& output_path,
    const SecureString& cover_password,
    const SecureString* hidden_password,
    const DeniableContainerOptions& options = {}
);

// Opens whichever authenticated slot matches password. Both slots are always
// tested; no slot kind is reported. Wrong password and authentication failure
// produce the same error.
void open_deniable_container(
    const std::filesystem::path& input_path,
    const std::filesystem::path& output_path,
    const SecureString& password,
    const DeniableContainerOptions& options = {}
);

} // namespace minicrypto

#endif // MINICRYPTO_DENIABLE_H
