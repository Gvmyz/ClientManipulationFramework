#pragma once

#include <window.h>

#include "WinHandle.h"

namespace PT::ProcessThread {
	WinHandle create_remote_thread(const WinHandle& process, LPTHREAD_START_ROUTINE start_routine, void* parameter);

	DWORD wait_for_thread(const WinHandle& thread, DWORD timeout_ms = INFINITE);

	bool get_thread_exit_code(const WinHandle& thread, DWORD& exit_code);
}
