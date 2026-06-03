#pragma once

#include <Windows.h>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "WinHandle.h"

namespace PT::MemoryPatch {
    struct PatchOutcome {
        std::uintptr_t address;
        std::size_t bytes_written;
        DWORD previous_protection;  // 0 unless change_protection was true
        bool protection_restored;
    };

    // Set change_protection=true when targeting .text or .rdata; unnecessary for
    // already-writable regions (.data, heap, stack).
    std::optional<PatchOutcome> patch_bytes(
        const WinHandle& process,
        std::uintptr_t address,
        const std::vector<std::uint8_t>& bytes,
        bool change_protection = false
    );

    std::optional<std::vector<std::uint8_t>> read_bytes(
        const WinHandle& process,
        std::uintptr_t address,
        std::size_t count
    );
}
