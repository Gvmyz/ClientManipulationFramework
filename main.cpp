#include <iostream>

#include <windows.h>
#include <psapi.h>

#include "inspector.h"
#include "window.h"
#include "Memory.h"
#include <vector>	
#include "WinHandle.h"
#include <string_view>
#include "Process.h"


void print_memory_info(const PT::MemoryInfo& mbi) {
	std::cout << "BaseAddress: 0x" << std::hex
		<< mbi.base_address << '\n';
	std::cout << "AllocationBase: 0x"
		<< mbi.allocation_base << '\n';
	std::cout << "RegionSize: " << std::dec
		<< mbi.region_size << '\n';
	std::cout << "State: " << PT::Memory::get_state_name(mbi.state) << '\n';
	std::cout << "Protect: " << PT::Memory::get_protect_name(mbi.protect) << '\n';
	std::cout << "Type: " << PT::Memory::get_type_name(mbi.type) << "\n\n";
}

void print_memory_infos(const std::vector<PT::MemoryInfo>& memory_infos) {
	for (const auto& mbi : memory_infos) {
		print_memory_info(mbi);
	}
}

void print_processes() {
	const auto processes = PT::get_processes();

	// Print the name and process identifier for each process.
	for (const auto pid : processes) {
		if (const auto path = PT::get_process_image_path(pid)) {
			std::wcout << L"PID: " << pid << L" | " << *path << L'\n';
		}
	}
}


int main(int argc, char** argv) {
	const unsigned int ppid = 20736;
	const std::uintptr_t address = 0x00000089752FF850ULL;

	auto proc = PT::Process::open_process(ppid, PROCESS_ALL_ACCESS);
	if (!proc) {
		std::cerr << "Failed to open process\n";
		return 1;
	}
	std::cout << "[+] Successfully opened process " << ppid << "\n";

	char test[128] = "Hello from the other side!";
	char res[128]{};

	std::string t{};
	auto allocated = PT::Memory::allocate_and_write(proc, test, sizeof(test));

	if (!allocated) {
		std::cerr << "Failed to allocate memory\n";
		std::cerr << GetLastError() << "\n";
		return 1;
	}
	std::cout << "[+] Successfully allocated memory at 0x" << std::hex << *allocated << "\n";

	std::cout << "\n[*]Memory region in the target process:\n";
	if (auto mem = PT::Memory::get_memory_info(proc, *allocated)) {
		print_memory_info(*mem);
	} else {
		std::cerr << "Failed to get memory info\n";
	}

	if (PT::Memory::read_memory(proc, *allocated, res, sizeof(res))) {
		std::cout << "[+] Successfully read memory: " << res << "\n";
	} else {
		std::cerr << "Failed to read memory\n";
	}

	/*if (PT::Memory::free_memory(proc, *allocated, 0, MEM_RELEASE)) {
		std::cout << "[+] Successfully freed memory at 0x" << std::hex << *allocated << "\n";
	} else {
		std::cerr << "Failed to free memory\n";
		std::cerr << GetLastError() << "\n";
	}

	std::cout << "\n[*]Memory region in the target process:\n";
	if (auto mem = PT::Memory::get_memory_info(proc, *allocated)) {
		print_memory_info(*mem);
	} else {
		std::cerr << "Failed to get memory info\n";
	}*/
	return 0;
}

