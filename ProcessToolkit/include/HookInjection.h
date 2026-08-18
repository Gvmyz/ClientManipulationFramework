#pragma once

#include <Windows.h>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "WinHandle.h"

namespace PT::HookInjection {
	struct HookOutcome {
		std::uintptr_t target_function;
		std::uintptr_t trampoline_base;
		std::size_t hook_bytes_size;      // JMP length (14 on x64, 5 on x86)
		std::size_t preserved_bytes;      // total bytes overwritten and preserved
		DWORD previous_protection;        // .text protection before RWX flip
		bool protection_restored;
		std::vector<std::uint8_t> original_prologue;
	};

	// Install a cross-process inline hook at target_function in the target
	// process. Overwrites the first `preserve_bytes` bytes of the target
	// function with (a) the JMP instruction and (b) NOP padding to reach
	// `preserve_bytes`. The trampoline atomically increments a counter at
	// trampoline_base+0, executes the original `preserve_bytes` bytes verbatim,
	// then jumps back to target_function + preserve_bytes.
	//
	// The JMP itself is a fixed length per architecture:
	//   14 bytes on x64 (absolute JMP via `FF 25 00 00 00 00` + 8-byte address)
	//    5 bytes on x86 (relative JMP via `E9 <rel32>`)
	//
	// preserve_bytes must be >= the JMP length. When larger, the extra bytes
	// after the JMP in the target are filled with NOPs (0x90); this lets the
	// caller pad the overwrite up to the next natural x86/x64 instruction
	// boundary so the preserved prologue never contains a chopped instruction.
	// Pass 0 to use the JMP length as-is.
	//
	// Cross-process events fired on a successful install:
	//   1 ALLOCVM_REMOTE  (trampoline page, RWX)
	//   1 READVM_REMOTE   (reading original prologue)
	//   1 WRITEVM_REMOTE  (writing trampoline into allocated page)
	//   1 PROTECTVM_REMOTE(.text → RWX)
	//   1 WRITEVM_REMOTE  (writing JMP+NOPs into .text at target_function)
	//   1 PROTECTVM_REMOTE(.text restore)
	std::optional<HookOutcome> install_inline_hook(
		const WinHandle& process,
		std::uintptr_t target_function,
		std::size_t preserve_bytes = 0
	);

	// Read the trampoline's hit counter (uint64_t on x64, uint32_t on x86 —
	// widened here to uint64_t for a uniform return type). A nonzero value
	// means the hooked function has been executed at least once since the
	// hook was installed.
	std::optional<std::uint64_t> read_hit_counter(
		const WinHandle& process,
		std::uintptr_t trampoline_base
	);
}
