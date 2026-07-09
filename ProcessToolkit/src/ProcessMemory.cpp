#include "ProcessMemory.h"


namespace PT::ProcessMemory {
	WinHandle open_process(DWORD pid) {
		HANDLE handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, FALSE, pid);
		return WinHandle(handle);
	}

	WinHandle open_process_memory_only(DWORD pid, bool need_read) {
		DWORD desired = PROCESS_VM_OPERATION | PROCESS_VM_WRITE;
		if (need_read) desired |= PROCESS_VM_READ;
		HANDLE handle = OpenProcess(desired, FALSE, pid);
		return WinHandle(handle);
	}

	void* remote_alloc(const WinHandle& process, SIZE_T size, DWORD protection) {
		if (!process || size == 0) return nullptr;
		return VirtualAllocEx(process.get(), nullptr, size, MEM_COMMIT | MEM_RESERVE, protection);
	}

	bool remote_free(const WinHandle& process, void* remote_address) {
		if (!process || !remote_address) return false;
		return VirtualFreeEx(process.get(), remote_address, 0, MEM_RELEASE);
	}

	bool remote_write(const WinHandle& process, void* remote_address, const void* data, SIZE_T size) {
		if (!process || !remote_address || !data || size == 0) return false;
		SIZE_T bytesWritten = 0;
		BOOL ok = WriteProcessMemory(process.get(), remote_address, data, size, &bytesWritten);
		return ok && bytesWritten == size;
	}

	bool remote_read(const WinHandle& process, const void* remote_address, void* buffer, SIZE_T size) {
		if (!process || !remote_address || !buffer || size == 0) return false;
		SIZE_T bytesRead = 0;
		BOOL ok = ReadProcessMemory(process.get(), remote_address, buffer, size, &bytesRead);
		return ok && bytesRead == size;
	}
}