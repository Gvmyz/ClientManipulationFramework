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
#include "Utils.h"


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
	PT::Cli::enable_ansi();
	const unsigned int ppid = 22400;
	const std::uintptr_t val_address = 0x00000089752FF850ULL;
	const std::uintptr_t hello_address = 0x00007FF7640D1000ULL;
	const std::wstring_view dll_path{L"C:\\Users\\alexs\\TU_WIEN\\THESIS\\Projects\\ClientManipulationFramework\\ProcessToolkit\\x64\\Release\\TestDll.dll"};
	const std::wstring_view dll_name{L"TestDll.dll"};
	const std::string_view dll_function_name{"RunTest"};

	PT::Cli::print_section("Local DLL Loading");
	auto local_dll_base = PT::Injector::local_inject(dll_path);
	PT::Cli::run_step("Inject DLL", local_dll_base.has_value());



	PT::Cli::print_section("Open Target Process");
	auto proc = PT::Process::open_process(ppid, PROCESS_ALL_ACCESS);
	PT::Cli::run_step(std::format("Opened process {}", ppid), proc.valid());

	PT::Cli::print_section("Inject DLL");
	auto exit_code = PT::Injector::inject_dll(proc, dll_path);
	PT::Cli::run_step("Injected DLL", exit_code.has_value());

	PT::Cli::print_section("Find Remote Module");
	auto dll_base = PT::Memory::find_module_base(proc, dll_name);
	PT::Cli::run_step(std::format("Found remote module base"), dll_base.has_value());
	PT::Cli::print_named_hex("Remote DLL base", *dll_base);

	PT::Cli::print_section("Call Exported Function");
	bool injection_result = PT::Injector::call_injected_function(proc, dll_name, *dll_base, dll_function_name);
	PT::Cli::run_step(std::format("Called function {}", dll_function_name), injection_result);

	return 0;
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

}

