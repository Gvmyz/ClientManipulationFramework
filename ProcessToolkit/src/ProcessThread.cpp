#include "ProcessThread.h"
#include "DirectSyscall.h"

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

namespace PT::ProcessThread {
	WinHandle create_remote_thread(const WinHandle& process, LPTHREAD_START_ROUTINE start_routine, void* parameter) {
		if (!process || !start_routine) return WinHandle();
		if (PT::DirectSyscall::IsEnabled()) {
			// NtCreateThreadEx path: direct-syscall dispatch bypasses
			// kernel32!CreateRemoteThread + ntdll!NtCreateThreadEx and
			// enters the kernel via `syscall` from DirectSyscallStubs.asm.
			// THREAD_ALL_ACCESS mirrors CreateRemoteThread's default.
			HANDLE thread = nullptr;
			NTSTATUS s = PT::DirectSyscall::NtCreateThreadEx(
				&thread,
				THREAD_ALL_ACCESS,
				nullptr,              // ObjectAttributes: default
				process.get(),
				reinterpret_cast<PVOID>(start_routine),
				parameter,
				0,                    // CreateFlags: not suspended
				0,                    // ZeroBits
				0,                    // StackSize: default
				0,                    // MaximumStackSize: default
				nullptr);             // AttributeList
			if (!NT_SUCCESS(s) || !thread) return WinHandle();
			return WinHandle(thread);
		}
		HANDLE thread = CreateRemoteThread(process.get(), nullptr, 0, start_routine, parameter, 0, nullptr);
		return WinHandle(thread);
	}

	DWORD wait_for_thread(const WinHandle& thread, DWORD timeout_ms) {
		if (!thread) return WAIT_FAILED;
		return WaitForSingleObject(thread.get(), timeout_ms);
	}

	bool get_thread_exit_code(const WinHandle& thread, DWORD& exit_code) {
		if (!thread) return false;
		return GetExitCodeThread(thread.get(), &exit_code);
	}
}
