#include "Memory.h"

#include <vector>
#include <iostream>	
#include "WinHandle.h"

#include <cstdint>
#include <cstddef>
#include <windows.h>
#include <string_view>
#include <optional>

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

		std::optional<std::uintptr_t> allocate_memory(const WinHandle& process, std::size_t size, DWORD allocation_type, DWORD protect) {
			if (!process) return std::nullopt;
			LPVOID addr = VirtualAllocEx(process.get(), nullptr, size, allocation_type, protect);
			if (!addr) {
				return std::nullopt;
			}
			return reinterpret_cast<std::uintptr_t>(addr);
		}

		bool free_memory(const WinHandle& process, std::uintptr_t address, std::size_t size, DWORD free_type) {
			if (!process) return false;
			return VirtualFreeEx(process.get(), reinterpret_cast<LPVOID>(address), size, free_type) != 0;
		}

		bool read_memory(const WinHandle& process, std::uintptr_t address, void* buffer, std::size_t size) {
			if (!process) return false;
			SIZE_T bytesRead = 0;
			return ReadProcessMemory(process.get(), reinterpret_cast<LPCVOID>(address), buffer, size, &bytesRead) && bytesRead == size;
		}

		bool write_memory(const WinHandle& process, std::uintptr_t address, const uintptr_t buffer, std::size_t size) {
			if (!process) return false;
			SIZE_T bytesWritten = 0;
			return WriteProcessMemory(process.get(), reinterpret_cast<LPVOID>(address), reinterpret_cast<LPVOID>(buffer), size, &bytesWritten) && bytesWritten == size;
		}

		std::optional<std::uintptr_t> allocate_and_write(const WinHandle& process, const void* buffer, std::size_t size, DWORD allocation_type, DWORD protect) {
			if (!process) return std::nullopt;
			auto allocated = allocate_memory(process, size, allocation_type, protect);
			if (!allocated) return std::nullopt;
			if (!write_memory(process, *allocated, reinterpret_cast<std::uintptr_t>(buffer), size)) {
				free_memory(process, *allocated, size);
				return std::nullopt;
			}
			return allocated;
		}
	}
}