#pragma once

#include <Windows.h>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "WinHandle.h"

namespace PT::SectionInjection {

	// Outcome of a section-mapped hollowing install. All fields are attacker-
	// side: `local_view_base` is the address in the attacker's process where
	// the shared section was mapped for local write / local verification read.
	// `remote_view_base` is the address in the victim where the same physical
	// pages are mapped — where the redirected thread actually executes.
	struct SectionHollowOutcome {
		DWORD          victim_pid;
		DWORD          victim_thread_id;
		std::uintptr_t local_view_base;   // attacker's view of the section
		std::uintptr_t remote_view_base;  // victim's view of the same section
		std::size_t    section_size;      // bytes committed to the section
		std::size_t    counter_offset;    // where the hit counter lives (offset 0)
		std::size_t    shellcode_offset;  // where the shellcode entry sits
	};

	// Section-Mapped Process Hollowing (documented advanced variant of
	// T1055.012; combines section-based payload delivery with hollowing's
	// suspended-process orchestration).
	//
	// Full flow:
	//   1.  CreateProcess(victim_exe, CREATE_SUSPENDED)                — victim frozen at LdrpInitializeProcess
	//   2.  NtCreateSection(SEC_COMMIT, RWX, section_size)             — pagefile-backed shared section
	//   3.  NtMapViewOfSection(section, GetCurrentProcess(), ...)      — attacker's local RW view
	//   4.  memcpy shellcode + zeroed counter into local view          — LOCAL, invisible to ETW-TI
	//   5.  NtMapViewOfSection(section, victim_process, ...)           — REMOTE, fires MAPVIEW_REMOTE
	//   6.  SetThreadContext(main_thread, RIP=remote_view+shellcode)   — fires SETTHREADCONTEXT_REMOTE
	//   7.  ResumeThread(main_thread)                                  — shellcode runs in victim
	//
	// Cross-process ETW-TI events fired on a successful install:
	//   1 MAPVIEW_REMOTE       (attacker → victim, the section map)
	//   1 SETTHREADCONTEXT_REMOTE (attacker → victim, RIP redirect)
	//   1 OpenProcess / OpenThread (via CreateProcess; caught by KernelProcess)
	// Notably absent:
	//   0 ALLOCVM_REMOTE       (no VirtualAllocEx — section delivery replaces it)
	//   0 WRITEVM_REMOTE       (no WriteProcessMemory — shared physical pages replace it)
	//   0 THREAD_CREATE_REMOTE (no CreateRemoteThread — victim's original thread runs the payload)
	//
	// Classifier expectation: fires `section_mapping.ti_mapview` at rule
	// position 1 in the cascade; the alternate `thread_hijack` and
	// `injection.catchall` rules would also match but the more specific
	// section-mapping label wins.
	//
	// Verification: the shellcode does `lock inc qword ptr [rip - X]` where X
	// resolves to the counter's offset within the section. The counter lives
	// at section offset 0. Since the attacker's local view and the victim's
	// remote view point to the SAME physical pages, the attacker can read the
	// counter from its own view (local memcpy) — no cross-process read
	// needed for verification. Nonzero counter after brief sleep proves the
	// shellcode ran; zero after N seconds indicates the victim never reached
	// the redirected RIP (usually a bad address setup).
	// unmap_original_image = true enables the MITRE T1055.012-aligned step of
	// calling NtUnmapViewOfSection on the victim's original .exe image before
	// mapping our section. Adds the KERNEL_THREATINT_TASK_UNMAPVIEW cross-
	// process event to the fingerprint — a distinctive syscall in the
	// hollowing recipe. Default false because on Windows 11 24H2 the unmap
	// step disrupts the subsequent SetThreadContext+ResumeThread path (the
	// shellcode never actually executes) — a real trade-off documented in
	// the hollowing literature as motivating "no-unmap" variants used by
	// modern malware for reliability on current Windows builds.
	std::optional<SectionHollowOutcome> install_section_mapped_hollowing(
		const std::wstring& victim_exe_path,
		bool unmap_original_image = false
	);

	// Read the hit counter from the attacker's own local view of the section.
	// LOCAL access — no cross-process API — so this is atomic + invisible to
	// ETW-TI (the shellcode's write into the shared section is also a local
	// write from the victim's perspective).
	std::uint64_t read_hit_counter_local(std::uintptr_t local_view_base);

	// Clean shutdown: unmap the attacker's local view, terminate the victim
	// process, close its handles. Meant to be called in the manipulation's
	// finally-equivalent so we don't leave zombied CREATE_SUSPENDED processes
	// or leaked section views on failure paths.
	void cleanup(const SectionHollowOutcome& outcome, HANDLE victim_process, HANDLE victim_thread);

	// Retrieve the victim process/thread handles from the most recent
	// successful install_section_mapped_hollowing() call. The single-slot
	// pattern is safe because the CLI calls install → verify → cleanup
	// sequentially. Returns NULL if no install has succeeded this session.
	HANDLE take_last_victim_process_handle();
	HANDLE take_last_victim_thread_handle();

}  // namespace PT::SectionInjection
