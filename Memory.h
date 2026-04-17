#pragma once

#include <cstdint>
#include <cstddef>
#include <windows.h>
#include <string_view>
#include <vector>
#include <optional>
#include <Psapi.h>

#include "WinHandle.h"

namespace PT {

	struct MemoryInfo {
		std::uintptr_t base_address;
		std::uintptr_t allocation_base;
		std::size_t region_size;
		DWORD state;
		DWORD protect;
		DWORD type;
	};

	namespace Memory {
		// Convert Windows' MEMORY_BASIC_INFORMATION to our MemoryInfo
		MemoryInfo convert_to_memory_info(const MEMORY_BASIC_INFORMATION& mbi);

		// Enumerate memory regions for a process handle
		std::vector<MemoryInfo> get_memory_infos(const WinHandle& process);

		// Query a single region containing address; returns std::optional<MemoryInfo>
		std::optional<MemoryInfo> get_memory_info(const WinHandle& process, std::uintptr_t address);

		// Change to std::optional<int>
		// Templated safe reader : returns true on success and writes to out
		template<typename T>
		bool read_trivial_memory(const WinHandle& process, std::uintptr_t address, T& out) {
			if (!process) return false;
			SIZE_T bytesRead = 0;
			return ReadProcessMemory(process.get(), reinterpret_cast<LPCVOID>(address), &out, sizeof(T), &bytesRead) && bytesRead == sizeof(T);
		}

		bool read_memory(const WinHandle& process, std::uintptr_t address, void* buffer, std::size_t size);

		template<typename T>
		bool write_trivial_memory(const WinHandle& process, std::uintptr_t address, const T& value) {
			if (!process) return false;
			SIZE_T bytesWritten = 0;
			return WriteProcessMemory(process.get(), reinterpret_cast<LPVOID>(address), &value, sizeof(T), &bytesWritten) && bytesWritten == sizeof(T);
		}

		bool write_memory(const WinHandle& process, std::uintptr_t address, const void* buffer, std::size_t size);


		// Add allocate_specific_memory if needed (VirtualAllocEx with an address hint) (Code caves, manual mapping, etc.)
		// Allocate memory in the target process; returns the base address of the allocated region on success
		std::optional<std::uintptr_t> allocate_memory(const WinHandle& process, std::size_t size, DWORD allocation_type = MEM_COMMIT | MEM_RESERVE, DWORD protect = PAGE_EXECUTE_READWRITE);

		// Free memory in the target process; returns true on success
		bool free_memory(const WinHandle& process, std::uintptr_t address, std::size_t size, DWORD free_type = MEM_RELEASE);

		// Write to a new memory region (allocate + write); returns the base address of the allocated region on success
		template<typename T>
		std::optional<std::uintptr_t> trivial_allocate_and_write(const WinHandle& process, const T& value, DWORD allocation_type = MEM_COMMIT | MEM_RESERVE, DWORD protect = PAGE_EXECUTE_READWRITE) {
			if (!process) return std::nullopt;
			auto allocated = allocate_memory(process, sizeof(T), allocation_type, protect);
			if (!allocated) return std::nullopt;
			if (!write_memory<T>(process, *allocated, value)) {
				free_memory(process, *allocated, sizeof(T));
				return std::nullopt;
			}
			return allocated;
		}

		std::optional<std::uintptr_t> allocate_and_write(const WinHandle& process, const void* buffer, std::size_t size, DWORD allocation_type = MEM_COMMIT | MEM_RESERVE, DWORD protect = PAGE_EXECUTE_READWRITE);

		// Check if a region is readable (simple check using protect flags)
		bool is_readable(const MemoryInfo& mi);

		// Helpers to get string names
		const std::string_view get_state_name(DWORD state);
		const std::string_view get_protect_name(DWORD protect);
		const std::string_view get_type_name(DWORD type);


		std::vector<MemoryInfo> filter_committed_regions(std::vector<MemoryInfo> mem_infos);
		std::vector<MemoryInfo> filter_private_regions(std::vector<MemoryInfo> mem_infos);
		std::vector<MemoryInfo> filter_executable_regions(std::vector<MemoryInfo> mem_infos);

		std::optional<WinHandle> create_thread(const WinHandle& process, std::uintptr_t start_address, void* parameter = nullptr, DWORD creation_flags = 0);


		std::optional<DWORD> get_thread_exit_code(const WinHandle& thread);

		std::optional<DWORD> wait_for_thread_exit_code(const WinHandle& thread, DWORD wait_time = INFINITE);

		std::optional<uintptr_t> find_module_base(const WinHandle& process, const std::wstring_view& module_name, DWORD filter_flag = LIST_MODULES_64BIT);
	}
}
