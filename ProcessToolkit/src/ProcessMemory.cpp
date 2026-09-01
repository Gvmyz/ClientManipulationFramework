#include "ProcessMemory.h"
#include "DirectSyscall.h"

// NT_SUCCESS helper; some SDK configurations don't expose it via <windows.h>.
#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

namespace PT::ProcessMemory {

	// ------------------------------------------------------------------
	// Cross-process primitives used by DllInjection, HookInjection, etc.
	//
	// Each primitive has a two-path body:
	//   - When DirectSyscall::IsEnabled() is true (i.e. the run was
	//     started with --via-direct-syscall), the syscall is emitted
	//     directly from the Nt* stub in DirectSyscallStubs.asm, bypassing
	//     every user-mode hook on ntdll's exports (which is the RQ3
	//     evasion axis).
	//   - Otherwise the original Win32 wrapper is used, matching the
	//     baseline behaviour these tests depended on before the
	//     direct-syscall layer existed.
	//
	// Both paths reach the same kernel handler, so ETW-TI events fire
	// identically. The observable difference is only in whether ntdll's
	// export was invoked at all -- which is what --observe-usermode-hooks
	// measures.
	// ------------------------------------------------------------------

	WinHandle open_process(DWORD pid) {
		constexpr DWORD desired = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
		                        | PROCESS_VM_WRITE | PROCESS_VM_OPERATION
		                        | PROCESS_CREATE_THREAD;
		if (PT::DirectSyscall::IsEnabled()) {
			HANDLE handle = nullptr;
			OBJECT_ATTRIBUTES oa{};
			oa.Length = sizeof(oa);
			PtClientId cid{ reinterpret_cast<HANDLE>(static_cast<uintptr_t>(pid)), nullptr };
			NTSTATUS s = PT::DirectSyscall::NtOpenProcess(&handle, desired, &oa, &cid);
			if (!NT_SUCCESS(s) || !handle) return WinHandle();
			return WinHandle(handle);
		}
		HANDLE handle = OpenProcess(desired, FALSE, pid);
		return WinHandle(handle);
	}

	WinHandle open_process_memory_only(DWORD pid, bool need_read) {
		DWORD desired = PROCESS_VM_OPERATION | PROCESS_VM_WRITE;
		if (need_read) desired |= PROCESS_VM_READ;
		if (PT::DirectSyscall::IsEnabled()) {
			HANDLE handle = nullptr;
			OBJECT_ATTRIBUTES oa{};
			oa.Length = sizeof(oa);
			PtClientId cid{ reinterpret_cast<HANDLE>(static_cast<uintptr_t>(pid)), nullptr };
			NTSTATUS s = PT::DirectSyscall::NtOpenProcess(&handle, desired, &oa, &cid);
			if (!NT_SUCCESS(s) || !handle) return WinHandle();
			return WinHandle(handle);
		}
		HANDLE handle = OpenProcess(desired, FALSE, pid);
		return WinHandle(handle);
	}

	void* remote_alloc(const WinHandle& process, SIZE_T size, DWORD protection) {
		if (!process || size == 0) return nullptr;
		if (PT::DirectSyscall::IsEnabled()) {
			PVOID   base = nullptr;
			SIZE_T  region = size;
			NTSTATUS s = PT::DirectSyscall::NtAllocateVirtualMemory(
				process.get(), &base, 0, &region, MEM_COMMIT | MEM_RESERVE, protection);
			if (!NT_SUCCESS(s) || !base) return nullptr;
			return base;
		}
		return VirtualAllocEx(process.get(), nullptr, size, MEM_COMMIT | MEM_RESERVE, protection);
	}

	bool remote_free(const WinHandle& process, void* remote_address) {
		if (!process || !remote_address) return false;
		// NtFreeVirtualMemory not in the DirectSyscall set (it isn't a
		// Sysmon-visible event and doesn't affect the RQ3 story). Baseline
		// path both when direct syscalls are on and off.
		return VirtualFreeEx(process.get(), remote_address, 0, MEM_RELEASE);
	}

	bool remote_write(const WinHandle& process, void* remote_address, const void* data, SIZE_T size) {
		if (!process || !remote_address || !data || size == 0) return false;
		SIZE_T bytesWritten = 0;
		if (PT::DirectSyscall::IsEnabled()) {
			NTSTATUS s = PT::DirectSyscall::NtWriteVirtualMemory(
				process.get(),
				remote_address,
				const_cast<PVOID>(data),
				size,
				&bytesWritten);
			return NT_SUCCESS(s) && bytesWritten == size;
		}
		BOOL ok = WriteProcessMemory(process.get(), remote_address, data, size, &bytesWritten);
		return ok && bytesWritten == size;
	}

	bool remote_read(const WinHandle& process, const void* remote_address, void* buffer, SIZE_T size) {
		if (!process || !remote_address || !buffer || size == 0) return false;
		SIZE_T bytesRead = 0;
		if (PT::DirectSyscall::IsEnabled()) {
			NTSTATUS s = PT::DirectSyscall::NtReadVirtualMemory(
				process.get(),
				const_cast<PVOID>(remote_address),
				buffer,
				size,
				&bytesRead);
			return NT_SUCCESS(s) && bytesRead == size;
		}
		BOOL ok = ReadProcessMemory(process.get(), remote_address, buffer, size, &bytesRead);
		return ok && bytesRead == size;
	}
}