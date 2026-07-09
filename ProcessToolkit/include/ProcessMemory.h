#pragma once

#include <window.h>

#include "WinHandle.h"


namespace PT::ProcessMemory {
	// Opens a target with the full injection mask (VM_READ | VM_WRITE |
	// VM_OPERATION | CREATE_THREAD | QUERY_INFORMATION). Use for DLL injection
	// paths (loadlibrary, threadhijack, manualmap) that need to allocate,
	// write, and create a remote thread.
	WinHandle open_process(DWORD pid);

	// Opens a target with the minimum mask needed for a pure memory-write
	// technique: VM_OPERATION | VM_WRITE, plus VM_READ iff the caller intends
	// to read back (e.g. --verify). No CREATE_THREAD, no QUERY_INFORMATION.
	// The resulting Sysmon-10 GrantedAccess distinguishes memory patching from
	// code injection at the ProcessAccess layer.
	WinHandle open_process_memory_only(DWORD pid, bool need_read);

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
