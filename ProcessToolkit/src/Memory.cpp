#include "Memory.h"

#include <vector>
#include <iostream>
#include "WinHandle.h"
#include "DirectSyscall.h"

#include <cstdint>
#include <cstddef>
#include <windows.h>
#include <string_view>
#include <optional>
#include <Psapi.h>

// Convenience: NT_SUCCESS is defined in ntdef.h / winternl.h; some SDK
// configurations don't pull it in via <windows.h>. Provide our own.
#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

namespace PT {
	namespace Memory {
		MemoryInfo convert_to_memory_info(const MEMORY_BASIC_INFORMATION& mbi) {
			return MemoryInfo{
				reinterpret_cast<std::uintptr_t>(mbi.BaseAddress),
				reinterpret_cast<std::uintptr_t>(mbi.AllocationBase),
				mbi.RegionSize,
				mbi.State,
				mbi.Protect,
				mbi.Type
			};
		}

		std::vector<MemoryInfo> get_memory_infos(const WinHandle& process) {
			std::vector<MemoryInfo> results{};
			if (!process) return results;

			MEMORY_BASIC_INFORMATION mbi{};
			std::uintptr_t addr = 0;
			while (VirtualQueryEx(process.get(), reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == sizeof(mbi)) {
				results.push_back(convert_to_memory_info(mbi));
				auto next = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
				if (next <= addr) {
					// Prevent infinite loop on overflow
					break;
				}
				addr = next;
			}
			return results;
		}

		std::optional<MemoryInfo> get_memory_info(const WinHandle& process, std::uintptr_t address) {
			if (!process) return std::nullopt;
			MEMORY_BASIC_INFORMATION mbi{};
			if (VirtualQueryEx(process.get(), reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == 0) {
				return std::nullopt;
			}
			return convert_to_memory_info(mbi);
		}

		bool is_readable(const MemoryInfo& mi) {
			// Check if the region is committed and has any of the readable flags
			if (mi.state != MEM_COMMIT) {
				return false;
			}
			constexpr DWORD readable_flags = PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE;
			return (mi.protect & readable_flags) != 0;
		}



		const std::string_view get_state_name(DWORD state) {
			switch (state) {
				case MEM_COMMIT: return "Committed";
				case MEM_FREE: return "Free";
				case MEM_RESERVE: return "Reserved";
				default: return "Unknown";
			}
		}
		const std::string_view get_protect_name(DWORD protect) {
			switch (protect) {
				case PAGE_NOACCESS: return "No Access";
				case PAGE_READONLY: return "Read-Only";
				case PAGE_READWRITE: return "Read/Write";
				case PAGE_EXECUTE: return "Execute";
				case PAGE_EXECUTE_READ: return "Execute/Read";
				case PAGE_EXECUTE_READWRITE: return "Execute/Read/Write";
				default: return "Unknown";
			}
		}
		const std::string_view get_type_name(DWORD type) {
			switch (type) {
				case MEM_IMAGE: return "Image";
				case MEM_MAPPED: return "Mapped";
				case MEM_PRIVATE: return "Private";
				default: return "Unknown";
			}
		}
		std::vector<MemoryInfo> filter_committed_regions(std::vector<MemoryInfo> mem_infos) {
			std::vector<MemoryInfo> results;
			for (const auto& mi : mem_infos) {
				if (mi.state == MEM_COMMIT) {
					results.push_back(mi);
				}
			}
			return results;
		}
		std::vector<MemoryInfo> filter_private_regions(std::vector<MemoryInfo> mem_infos) {
			std::vector<MemoryInfo> results;
			for (const auto& mi : mem_infos) {
				if (mi.type == MEM_PRIVATE) {
					results.push_back(mi);
				}
			}
			return results;
		}
		std::vector<MemoryInfo> filter_executable_regions(std::vector<MemoryInfo> mem_infos) {
			std::vector<MemoryInfo> results;
			for (const auto& mi : mem_infos) {
				constexpr DWORD executable_flags = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE;
				if ((mi.protect & executable_flags) != 0) {
					results.push_back(mi);
				}
			}
			return results;
		}

		// -----------------------------------------------------------------
		// Cross-process memory primitives.
		//
		// Each primitive has two code paths:
		//   * When DirectSyscall::IsEnabled() is true, we invoke the
		//     Nt* function directly (the syscall instruction is emitted
		//     from DirectSyscallStubs.asm). This bypasses every user-mode
		//     hook on the kernel32/ntdll exports, including Sysmon's.
		//   * Otherwise we call the Win32 wrapper as before. This is the
		//     baseline behavior used by every attack manifest that does
		//     not set the direct-syscall flag.
		//
		// Both paths reach the same kernel routine, so ETW-TI events fire
		// identically. The observable difference is at the user-mode
		// telemetry layer — Sysmon Event 8 / Event 10 / etc. stop firing
		// under the direct-syscall path. This is the empirical basis for
		// the RQ3 evasion axis: same primitive, same kernel event, but
		// zero visibility to user-mode-hooked instrumentation.
		// -----------------------------------------------------------------

		std::optional<std::uintptr_t> allocate_memory(const WinHandle& process, std::size_t size, DWORD allocation_type, DWORD protect) {
			if (!process) return std::nullopt;
			if (PT::DirectSyscall::IsEnabled()) {
				PVOID   base = nullptr;
				SIZE_T  region = size;
				NTSTATUS s = PT::DirectSyscall::NtAllocateVirtualMemory(
					process.get(), &base, 0, &region, allocation_type, protect);
				if (!NT_SUCCESS(s) || !base) return std::nullopt;
				return reinterpret_cast<std::uintptr_t>(base);
			}
			LPVOID addr = VirtualAllocEx(process.get(), nullptr, size, allocation_type, protect);
			if (!addr) {
				return std::nullopt;
			}
			return reinterpret_cast<std::uintptr_t>(addr);
		}

		bool free_memory(const WinHandle& process, std::uintptr_t address, std::size_t size, DWORD free_type) {
			if (!process) return false;
			// NtFreeVirtualMemory isn't wrapped by DirectSyscall (not on the
			// evasion-relevant set — it doesn't fire anything Sysmon watches).
			// Baseline VirtualFreeEx path both when direct syscalls are on and off.
			return VirtualFreeEx(process.get(), reinterpret_cast<LPVOID>(address), size, free_type) != 0;
		}

		bool read_memory(const WinHandle& process, std::uintptr_t address, void* buffer, std::size_t size) {
			if (!process) return false;
			SIZE_T bytesRead = 0;
			if (PT::DirectSyscall::IsEnabled()) {
				NTSTATUS s = PT::DirectSyscall::NtReadVirtualMemory(
					process.get(), reinterpret_cast<PVOID>(address), buffer, size, &bytesRead);
				return NT_SUCCESS(s) && bytesRead == size;
			}
			return ReadProcessMemory(process.get(), reinterpret_cast<LPCVOID>(address), buffer, size, &bytesRead) && bytesRead == size;
		}

		bool write_memory(const WinHandle& process, std::uintptr_t address, const void* buffer, std::size_t size) {
			if (!process) return false;
			SIZE_T bytesWritten = 0;
			if (PT::DirectSyscall::IsEnabled()) {
				NTSTATUS s = PT::DirectSyscall::NtWriteVirtualMemory(
					process.get(),
					reinterpret_cast<PVOID>(address),
					const_cast<PVOID>(buffer),
					size,
					&bytesWritten);
				return NT_SUCCESS(s) && bytesWritten == size;
			}
			return WriteProcessMemory(process.get(), reinterpret_cast<LPVOID>(address), buffer, size, &bytesWritten) && bytesWritten == size;
		}

		std::optional<std::uintptr_t> allocate_and_write(const WinHandle& process, const void* buffer, std::size_t size, DWORD allocation_type, DWORD protect) {
			if (!process) return std::nullopt;
			auto allocated = allocate_memory(process, size, allocation_type, protect);
			if (!allocated) return std::nullopt;
			if (!write_memory(process, *allocated, buffer, size)) {
				free_memory(process, *allocated, size);
				return std::nullopt;
			}
			return allocated;
		}

		// Might return a struct with ThreadID, exit code and handle if needed; for now just return the handle
		// Note: CreateRemoteThread can be used to execute code in the target process, but it has limitations (e.g., it may not work well with certain mitigations). For more advanced techniques, consider manual mapping or using APCs.
		std::optional<WinHandle> create_thread(const WinHandle& process, std::uintptr_t start_address, void* parameter, DWORD creation_flags) {
			if (!process) return std::nullopt;
			if (PT::DirectSyscall::IsEnabled()) {
				HANDLE threadHandle = nullptr;
				// THREAD_ALL_ACCESS mirrors what CreateRemoteThread requests.
				// The other args match ntdll's NtCreateThreadEx signature —
				// CreateRemoteThread is a thin wrapper around it.
				NTSTATUS s = PT::DirectSyscall::NtCreateThreadEx(
					&threadHandle,
					THREAD_ALL_ACCESS,
					nullptr,               // ObjectAttributes: default
					process.get(),
					reinterpret_cast<PVOID>(start_address),
					parameter,
					creation_flags,        // CREATE_SUSPENDED etc. flow through
					0,                     // ZeroBits
					0,                     // StackSize (default)
					0,                     // MaximumStackSize (default)
					nullptr);              // AttributeList
				if (!NT_SUCCESS(s) || !threadHandle) return std::nullopt;
				return WinHandle(threadHandle);
			}
			DWORD threadId{0}; // Optionally, you can capture the thread ID if needed
			HANDLE threadHandle = CreateRemoteThread(process.get(), nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(start_address), parameter, creation_flags, &threadId);
			if (!threadHandle) {
				return std::nullopt;
			}
			return WinHandle(threadHandle);
		}

		std::optional<DWORD> get_thread_exit_code(const WinHandle& thread) {
			if (!thread) return std::nullopt;
			DWORD exitCode{0};
			if (!GetExitCodeThread(thread.get(), &exitCode)) {
				return std::nullopt;
			}
			return exitCode;
		}

		std::optional<DWORD> wait_for_thread_exit_code(const WinHandle& thread, DWORD wait_time) {
			if (!thread) return std::nullopt;
			DWORD waitResult = WaitForSingleObject(thread.get(), wait_time);
			if (waitResult != WAIT_OBJECT_0) {
				return std::nullopt; // Wait failed or timed out
			}
			return get_thread_exit_code(thread);
		}

		std::optional<uintptr_t> find_module_base(const WinHandle& process, const std::wstring_view& module_name, DWORD filter_flag) {
			if (!process) return std::nullopt;
			HMODULE hMods[1024];
			DWORD cbNeeded;
			if (EnumProcessModulesEx(process.get(), hMods, sizeof(hMods), &cbNeeded, filter_flag)) {
				for (size_t i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
					wchar_t baseName[512];
					if (GetModuleBaseNameW(process.get(), hMods[i], baseName, 512)) {
						if (module_name == baseName) {
							return reinterpret_cast<std::uintptr_t>(hMods[i]);
						}
					}
				}
			}
			return std::nullopt; // Module not found
		}
	}
}