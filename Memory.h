#pragma once

#include <cstdint>
#include <cstddef>
#include <windows.h>
#include <string_view>
#include <vector>
#include <optional>

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

		// Templated safe reader : returns true on success and writes to out
		template<typename T>
		bool read_memory(const WinHandle& process, std::uintptr_t address, T& out);

		// Check if a region is readable (simple check using protect flags)
		bool is_readable(const MemoryInfo& mi);

		// Helpers to get string names
		const std::string_view get_state_name(DWORD state);
		const std::string_view get_protect_name(DWORD protect);
		const std::string_view get_type_name(DWORD type);


		std::vector<MemoryInfo> filter_committed_regions(std::vector<MemoryInfo> mem_infos);
		std::vector<MemoryInfo> filter_private_regions(std::vector<MemoryInfo> mem_infos);
		std::vector<MemoryInfo> filter_executable_regions(std::vector<MemoryInfo> mem_infos);
	}
}
