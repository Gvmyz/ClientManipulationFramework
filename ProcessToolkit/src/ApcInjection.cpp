#include "ApcInjection.h"

#include <TlHelp32.h>
#include <cstring>

#include "Memory.h"

namespace PT::ApcInjection {

	namespace {

		// Trampoline page layout — same shape as HookInjection's for consistency:
		//   [0x00] hit counter (uint64_t on x64, uint32_t on x86)
		//   [0x08..0x10] padding to align the shellcode nicely
		//   [0x10] shellcode start
		constexpr std::size_t TRAMPOLINE_SIZE  = 4096;
		constexpr std::size_t COUNTER_OFFSET   = 0x00;
		constexpr std::size_t SHELLCODE_OFFSET = 0x10;

#ifdef _WIN64
		// x64 APC shellcode. Windows x64 __fastcall passes the first argument
		// in RCX and cleans up its own stack, so a leaf APC routine that only
		// touches one arg needs no prologue.
		//
		// The Windows APC dispatcher (KiUserApcDispatcher) invokes the user's
		// routine as `void apc(ULONG_PTR Parameter)`; Parameter is whatever we
		// passed as QueueUserAPC's `dwData`. We pass counter_addr, so on entry
		// RCX == &hit_counter and we can atomically increment it in place.
		//
		//   F0 48 FF 01   lock inc qword ptr [rcx]   (4 bytes)
		//   C3            ret                        (1 byte)
		//                                            = 5 bytes total.
		//
		// `lock` prefix guarantees the increment is atomic even if the APC
		// fires on multiple target threads concurrently (only one thread does
		// in this build, but the prefix costs one byte and future-proofs it).
		std::vector<std::uint8_t> build_shellcode() {
			return {
				0xF0, 0x48, 0xFF, 0x01,   // lock inc qword ptr [rcx]
				0xC3,                     // ret
			};
		}

#else   // _WIN64

		// x86 APC shellcode. On x86 Win32 the APC dispatcher pushes the single
		// ULONG_PTR argument on the stack and calls the user routine using
		// __stdcall (callee cleans up), so the routine's stack on entry looks
		// like:
		//     [esp]     -> return address into KiUserApcDispatcher
		//     [esp+4]   -> ULONG_PTR Parameter   ==   &hit_counter
		//
		//   8B 44 24 04   mov eax, [esp+4]          ; eax = &hit_counter    (4 bytes)
		//   F0 FF 00      lock inc dword ptr [eax]  ; ++*counter atomically (3 bytes)
		//   C2 04 00      ret 4                     ; pop 4 bytes of arg    (3 bytes)
		//                                                                   = 10 bytes total.
		//
		// `ret 4` (not plain `ret`) is required because __stdcall makes the
		// callee responsible for the 4-byte argument cleanup. Getting this
		// wrong corrupts the target thread's stack on return.
		std::vector<std::uint8_t> build_shellcode() {
			return {
				0x8B, 0x44, 0x24, 0x04,   // mov eax, [esp+4]
				0xF0, 0xFF, 0x00,         // lock inc dword ptr [eax]
				0xC2, 0x04, 0x00,         // ret 4
			};
		}

#endif  // _WIN64

		// Pick the first non-attacker thread in `target_pid`. APCs are queued
		// onto a specific thread, so we need a TID. Simplest reproducible
		// choice: enumerate threads via Toolhelp and take the first one owned
		// by the target. This is usually the process's main thread and it's
		// the one that runs the app's message loop / main loop, i.e. the one
		// that's actually hitting alertable waits.
		//
		// We deliberately DO NOT try to filter for threads that are already
		// in an alertable wait — that would require querying each thread's
		// kernel state, which needs elevated access and isn't exposed via a
		// stable Win32 API. Taking the main thread is enough: TestTarget's
		// main loop hits SleepEx(TRUE) every 10ms, so the APC drains quickly.
		std::optional<DWORD> find_first_target_thread(DWORD target_pid) {
			if (target_pid == 0) return std::nullopt;
			HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
			if (snap == INVALID_HANDLE_VALUE) return std::nullopt;
			std::optional<DWORD> tid;
			THREADENTRY32 te{};
			te.dwSize = sizeof(te);
			if (Thread32First(snap, &te)) {
				do {
					if (te.th32OwnerProcessID == target_pid) {
						tid = te.th32ThreadID;
						break;
					}
				} while (Thread32Next(snap, &te));
			}
			CloseHandle(snap);
			return tid;
		}

	}  // anonymous namespace

	std::optional<ApcOutcome> queue_apc(
		const WinHandle& process,
		DWORD target_pid)
	{
		if (!process || target_pid == 0) return std::nullopt;

		// 1. Find a target thread to receive the APC. If the target has no
		//    threads (impossible for a live process, but guard anyway) we bail.
		auto tid = find_first_target_thread(target_pid);
		if (!tid) return std::nullopt;

		// 2. Open the target thread. We need THREAD_SET_CONTEXT for
		//    QueueUserAPC — it's a Win32 access-mask requirement documented on
		//    MSDN. THREAD_SET_CONTEXT is included in Sysmon's "hostile
		//    thread-access-mask" set, so opening even at this minimal privilege
		//    still shows up as a hostile process-access event.
		HANDLE raw_thread = OpenThread(THREAD_SET_CONTEXT, FALSE, *tid);
		if (!raw_thread) return std::nullopt;
		WinHandle target_thread(raw_thread);

		// 3. Allocate the trampoline page (RWX) in the target — same primitive
		//    as manualmap uses for its loader stub and shellcode.
		auto trampoline_base = PT::Memory::allocate_memory(
			process, TRAMPOLINE_SIZE,
			MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!trampoline_base) return std::nullopt;

		// 4. Assemble the trampoline buffer locally: full 4KB, zero-filled so
		//    the counter starts at 0, with the shellcode dropped at offset
		//    0x10. A single WriteProcessMemory call moves the whole buffer
		//    across process boundaries, producing ONE cross-process WRITEVM
		//    event rather than two.
		std::vector<std::uint8_t> trampoline_buffer(TRAMPOLINE_SIZE, 0);
		const auto shellcode = build_shellcode();
		std::memcpy(trampoline_buffer.data() + SHELLCODE_OFFSET,
					shellcode.data(), shellcode.size());

		if (!PT::Memory::write_memory(
				process, *trampoline_base,
				trampoline_buffer.data(), trampoline_buffer.size())) {
			PT::Memory::free_memory(process, *trampoline_base, 0);
			return std::nullopt;
		}

		// 5. Queue the APC. QueueUserAPC is the documented kernel32 wrapper
		//    around NtQueueApcThread; both hit the same kernel dispatch and
		//    fire the same ETW-TI event. Using the documented API keeps the
		//    call site auditable without needing ntdll's private symbol table.
		//
		//    We pass counter_addr as the APC parameter (dwData). The kernel
		//    forwards it as the ULONG_PTR argument to our shellcode, which
		//    reads it (via RCX on x64 / [esp+4] on x86) and increments the
		//    qword/dword at that address.
		//
		//    QueueUserAPC returns nonzero on success. If it fails (rare — the
		//    target thread has to exist and be openable at this access), we
		//    free the trampoline to avoid orphaning an RWX page in the target.
		const std::uintptr_t apc_routine = *trampoline_base + SHELLCODE_OFFSET;
		const std::uintptr_t counter     = *trampoline_base + COUNTER_OFFSET;

		const DWORD rc = QueueUserAPC(
			reinterpret_cast<PAPCFUNC>(apc_routine),
			target_thread.get(),
			static_cast<ULONG_PTR>(counter));
		if (rc == 0) {
			PT::Memory::free_memory(process, *trampoline_base, 0);
			return std::nullopt;
		}

		return ApcOutcome{
			.trampoline_base   = *trampoline_base,
			.apc_routine_addr  = apc_routine,
			.counter_addr      = counter,
			.target_thread_id  = *tid,
		};
	}

	std::optional<std::uint64_t> read_hit_counter(
		const WinHandle& process,
		std::uintptr_t counter_addr)
	{
		if (!process || counter_addr == 0) return std::nullopt;

#ifdef _WIN64
		std::uint64_t counter = 0;
		if (!PT::Memory::read_trivial_memory(process, counter_addr, counter)) {
			return std::nullopt;
		}
		return counter;
#else
		std::uint32_t counter = 0;
		if (!PT::Memory::read_trivial_memory(process, counter_addr, counter)) {
			return std::nullopt;
		}
		return static_cast<std::uint64_t>(counter);
#endif
	}

}  // namespace PT::ApcInjection
