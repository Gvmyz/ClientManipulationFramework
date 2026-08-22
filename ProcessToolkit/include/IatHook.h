#pragma once

#include <Windows.h>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "WinHandle.h"

namespace PT::IatHook {
	struct IatHookOutcome {
		std::uintptr_t iat_slot_va;         // absolute VA of the IAT entry we overwrote
		std::uintptr_t original_target_va;  // the pointer value the slot originally held
		std::uintptr_t trampoline_base;     // RWX page allocated for the detour
		std::uintptr_t counter_va;          // trampoline_base + COUNTER_OFFSET
		std::size_t    slot_size;           // 4 (x86) or 8 (x64)
	};

	// Install a cross-process IAT (Import Address Table) hook in `target_pid`.
	//
	// Finds the target's main image, walks its import descriptor table for the
	// requested (import_module, function_name) pair (case-insensitive on the
	// DLL name), allocates a small RWX trampoline in the target, writes a
	// counter-increment + absolute-jump-to-original shellcode into it, then
	// flips the IAT page RO -> RW, overwrites the slot with the trampoline
	// address, and restores the original protection. The trampoline does not
	// touch any GPRs (the counter increment uses a memory operand; the trailing
	// jump reads an absolute address from a co-located pointer), so any calling
	// convention the caller uses reaches the original function untouched.
	//
	// Cross-process events fired on a successful install (fingerprint):
	//   several READVM_REMOTE  (walking DOS/NT headers + import descriptors +
	//                           name strings + IAT entries — typically 6-12
	//                           small reads, dominates the read count)
	//   1 ALLOCVM_REMOTE       (trampoline page, RWX)
	//   1 WRITEVM_REMOTE       (trampoline shellcode write, ~4KB)
	//   1 PROTECTVM_REMOTE     (IAT page RO -> RW — reliably fires because
	//                           the IAT lives on a genuinely read-only page,
	//                           unlike a module .text page where PROTECTVM
	//                           can be silently suppressed by the kernel)
	//   1 WRITEVM_REMOTE       (slot overwrite: 8 bytes x64, 4 bytes x86 —
	//                           the pointer-sized write is the primary
	//                           distinguishing signal from inline hook, which
	//                           overwrites ~5-14 bytes of prologue in .text)
	//   1 PROTECTVM_REMOTE     (IAT page restore)
	//
	// Verification: the trampoline atomically increments a counter at
	// trampoline_base + COUNTER_OFFSET (uint64_t on x64, uint32_t on x86). The
	// caller reads it back with read_hit_counter after waiting long enough for
	// the target to have called the hooked import at least once. TestTarget's
	// main loop calls SleepEx(10, TRUE) every ~10 ms, so hooking kernel32.dll's
	// SleepEx entry yields hundreds of hits in a two-second verify window.
	std::optional<IatHookOutcome> install_iat_hook(
		const WinHandle& process,
		DWORD target_pid,
		std::wstring_view import_module,      // e.g. L"kernel32.dll"
		std::string_view function_name        // e.g. "SleepEx"
	);

	// Read the trampoline's hit counter. Nonzero => the target has called the
	// hooked import at least once since install_iat_hook returned.
	std::optional<std::uint64_t> read_hit_counter(
		const WinHandle& process,
		std::uintptr_t counter_va
	);
}
