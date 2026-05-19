#pragma once

#include <window.h>

#include "WinHandle.h"


namespace PT::ProcessMemory {
	WinHandle open_process(DWORD pid);

	void* remote_alloc(const WinHandle& process, SIZE_T size, DWORD protection = PAGE_EXECUTE_READWRITE);

	bool remote_free(
		const WinHandle& process,
		void* remote_address
	);

	bool remote_write(
		const WinHandle& process,
		void* remote_address,
		const void* data,
		SIZE_T size
	);

	bool remote_read(
		const WinHandle& process,
		const void* remote_address,
		void* buffer,
		SIZE_T size
	);
}
