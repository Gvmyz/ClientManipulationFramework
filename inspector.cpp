#include <iostream>
#include <string.h>
#include <vector>
#include <array>
#include <optional>

#include "Windows.h"
#include "Psapi.h"

#include "inspector.h"
#include "WinHandle.h"
#include "Process.h"


namespace PT {
	void hello() {
		std::cout << "Hello" << std::endl;
	}

	std::vector<DWORD> get_processes() {
		return Process::list_processes();
	}

	std::optional<std::wstring> get_process_image_path(DWORD processId) {
		return Process::get_image_path(processId);
	}

	WinHandle open_process(DWORD pid) {
		return Process::open_process(pid);
	}





	// Get back a vector<ModuleInfo>
	// Need to learn the privileges to list the modules
	void enumerate_modules(HANDLE hProcess) {
		HMODULE hMods[1024];
		DWORD cbNeeded;

		if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
			std::cout << "Gotten: " << cbNeeded << std::endl;
			for (size_t i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
				wchar_t baseName[512];
				if (GetModuleBaseNameW(hProcess, hMods[i], baseName, 512)) {
					std::wcout << baseName << std::endl;
				}
				MODULEINFO modInfo;
				if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
					std::cout << "EntryPoint: " << modInfo.EntryPoint << std::endl;
					std::cout << "Size: " << modInfo.SizeOfImage << std::endl;
					std::cout << "Base address: 0x" << std::hex
						<< reinterpret_cast<std::uintptr_t>(modInfo.lpBaseOfDll)
						<< std::dec << '\n';
				}
				else {
					std::cout << "Error opening module: " << i << std::endl;
				}

			}
		}
	}

	// Get back a vector<MemoryRegionInfo>
	/*std::vec enumerate_memory_regions(const WinHandle& proc) {
		if (proc.valid()) {
			std::cerr << "Invalid process handle\n";
			return;
		}
		MEMORY_BASIC_INFORMATION mbi{};
		unsigned char* addr = nullptr;
		while (VirtualQueryEx(proc.get(), addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
			std::cout << "BaseAddress: 0x" << std::hex
				<< reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) << '\n';

			std::cout << "AllocationBase: 0x"
				<< reinterpret_cast<std::uintptr_t>(mbi.AllocationBase) << '\n';

			std::cout << "RegionSize: " << std::dec
				<< mbi.RegionSize << '\n';

			std::cout << "State: 0x" << std::hex << mbi.State << '\n';
			std::cout << "Protect: 0x" << mbi.Protect << '\n';
			std::cout << "Type: 0x" << mbi.Type << "\n\n";

			addr = static_cast<unsigned char*>(mbi.BaseAddress) + mbi.RegionSize;
		}
	}*/

	void proc_inspect(int pid) {
		//print_process_name_and_id(pid);

		WinHandle process = Process::open_process(static_cast<DWORD>(pid));

		HMODULE hMod;
		DWORD cbNeeded;
		wchar_t baseName[512];

		if (EnumProcessModules(process.get(), &hMod, sizeof(hMod), &cbNeeded)) {
			GetModuleBaseNameW(process.get(), hMod, baseName, 512);
			std::wcout << baseName << std::endl;
		}

		enumerate_modules(process.get());

		// For feature 1
		// Get module information => Base address + size for all modules
		// Put that in enumerate_modules

		// Feature 2: Memory region viewer (enumerate_mem...)

	}
}
