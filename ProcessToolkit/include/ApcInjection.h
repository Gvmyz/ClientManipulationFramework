#pragma once

#include <Windows.h>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "WinHandle.h"

namespace PT::ApcInjection {
	struct ApcOutcome {
		std::uintptr_t trampoline_base;   // start of the RWX page in the target
		std::uintptr_t apc_routine_addr;  // shellcode entry (= trampoline_base + SHELLCODE_OFFSET)
		std::uintptr_t counter_addr;      // hit-counter address (= trampoline_base + COUNTER_OFFSET)
		DWORD target_thread_id;           // which target thread received the APC
	};

	// Cross-process APC injection: allocate an RWX page in the target, write a
	// tiny shellcode that increments a hit counter, then QueueUserAPC that
	// shellcode onto one of the target's threads. Unlike LoadLibrary / manual
	// mapping / thread hijack this DOES NOT create a new thread in the target
	// nor modify any thread's context — the target's existing thread runs the
	// payload the next time it enters an alertable wait (SleepEx / *Ex-style
	// waits). This is what makes APC injection (MITRE T1055.004) evade any
	// detector anchored on CreateRemoteThread / thread-start heuristics.
	//
	// Cross-process events fired on a successful install:
	//   1 OpenProcess     (attacker → target)
	//   1 OpenThread      (attacker → target thread)
	//   1 ALLOCVM_REMOTE  (RWX trampoline page, ~4KB)
	//   1 WRITEVM_REMOTE  (shellcode + zeroed counter into the allocated page)
	//   1 APC-injection   (the ETW-TI event dispatched by NtQueueApcThread)
	// Notably absent:
	//   0 THREAD_CREATE_REMOTE (unlike LoadLibrary / manual mapping)
	//   0 SETTHREADCONTEXT     (unlike thread hijack)
	std::optional<ApcOutcome> queue_apc(
		const WinHandle& process,
		DWORD target_pid
	);

	// Read the trampoline's hit counter. Nonzero means the target thread has
	// entered an alertable wait at least once since the APC was queued and
	// therefore executed our shellcode. Returns nullopt on RPM failure.
	std::optional<std::uint64_t> read_hit_counter(
		const WinHandle& process,
		std::uintptr_t counter_addr
	);
}
