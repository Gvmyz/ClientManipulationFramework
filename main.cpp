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
#include "Injector.h"


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
	const unsigned int ppid = 12828;
	const std::uintptr_t val_address = 0x00000089752FF850ULL;
	const std::uintptr_t hello_address = 0x00007FF7640D1000ULL;
	const std::wstring_view dll_path{L"C:\\Users\\alexs\\TU_WIEN\\THESIS\\Projects\\ProcessToolkit\\x64\\Release\\TestDll.dll"};
	const std::wstring_view dll_name{L"TestDll.dll"};
	const std::string_view dll_function_name{"RunTest"};

	auto local_dll_base = PT::Injector::local_inject(dll_path);
	if (!local_dll_base) {
		std::cerr << "[-] Failed to inject DLL into local process\n";
		return 1;
	}

	auto proc = PT::Process::open_process(ppid, PROCESS_ALL_ACCESS);
	if (!proc) {
		std::cerr << "Failed to open process\n";
		return 1;
	}
	std::cout << "[+] Successfully opened process " << ppid << "\n";

	auto exit_code = PT::Injector::inject_dll(proc, dll_path);
	if (exit_code) {
		std::cout << "[+] Successfully injected DLL\n";
	} else {
		std::cerr << "[-] Failed to inject DLL\n";
		return 1;
	}

	auto dll_base = PT::Memory::find_module_base(proc, dll_name);
	if (!dll_base) {
		std::cerr << "[-] Failed to find module base\n";
		return 1;
	}
	std::cout << "At base: 0x" << std::hex << *dll_base << "\n";

	if (PT::Injector::call_injected_function(proc, dll_name, *dll_base, dll_function_name)) {
		std::cout << "[+] Successfully called function " << dll_function_name << " in DLL\n";
		std::cout << "At base: 0x" << std::hex << *dll_base << "\n";
	} else {
		std::cerr << "[-] Failed to call function " << dll_function_name << " in DLL\n";
	}

	//PT::Injector::unload_dll(proc, L"C:\\Users\\alexs\\TU_WIEN\\THESIS\\Projects\\ProcessToolkit\\x64\\Release\\TestDll.dll");

	/*PT::Memory::create_thread(proc, hello_address);*/

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

