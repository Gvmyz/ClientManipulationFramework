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


int main(int argc, char** argv) {
	const unsigned int ppid = 20736;
	const std::uintptr_t address = 0x00000089752FF850ULL;

	//return run(charc, argv); // ImGui
	std::cout << "Hello world" << std::endl;

	const auto processes = PT::get_processes();

	// Print the name and process identifier for each process.
	for (const auto pid : processes) {
		if (const auto path = PT::get_process_image_path(pid)) {
			std::wcout << L"PID: " << pid << L" | " << *path << L'\n';
		}
	}

	auto proc = PT::Process::open_process(ppid, PROCESS_ALL_ACCESS);
	if (!proc) {
		std::cerr << "Failed to open process\n";
		return 1;
	}
	std::cout << "[+] Successfully opened process " << ppid << "\n";

	const auto memory_infos = PT::Memory::get_memory_infos(proc);

	print_memory_infos(memory_infos);

	int t = 0;
	std::byte buf[4]{};
	SIZE_T bytesRead = 0;

	if (const auto mbi = PT::Memory::get_memory_info(proc, address)) {
		print_memory_info(*mbi);
	}

	if (PT::Memory::read_memory<int>(proc, address, t)) {
		std::cout << "Value at address 0x" << std::hex << address << ": " << std::dec << t << '\n';
	}
	else {
		std::cerr << "Failed to read memory " << GetLastError() << '\n';
	}

	std::cout << "Bytes read: " << bytesRead << '\n';

	std::cout << "Now writing...\n";
	if (PT::Memory::write_memory<int>(proc, address, 1336)) {
		std::cout << "Successfully wrote to memory\n";
	}
	else {
		std::cerr << "Failed to write memory " << GetLastError() << '\n';
	}

	return 0;
}

