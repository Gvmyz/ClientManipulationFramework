#include "ProcessThread.h"

namespace PT::ProcessThread {
	WinHandle create_remote_thread(const WinHandle& process, LPTHREAD_START_ROUTINE start_routine, void* parameter) {
		if (!process || !start_routine) return WinHandle();
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
