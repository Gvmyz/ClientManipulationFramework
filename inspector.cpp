#include <iostream>
#include <string.h>
//#include <wchar.h>

#include "Windows.h"
#include "Psapi.h"

#include "inspector.h"


namespace inspector {
	void hello() {
		std::cout << "Hello" << std::endl;
	}

	void print_process_name_and_id(DWORD processID) {

		HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
			FALSE,
			processID);

		if (!hProcess) {
			std::cout << "Error while opening process" << std::endl;
			return;
		}
		wchar_t path[512];
		DWORD size = sizeof(path) / sizeof(wchar_t);
		if (QueryFullProcessImageNameW(hProcess, FALSE, path, &size)) {
			std::wcout << L"PID: " << processID << L" | " << path << std::endl;
			/*if (wcsstr(path, L"TestTarget")) {
				std::wcout << L"PID: " << processID << L" | " << path << std::endl;
			}*/
		}

		CloseHandle(hProcess);
	}

	// Proc Inspect => PID, image path, ...

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
	void enumerate_memory_regions(HANDLE hProcess) {
		MEMORY_BASIC_INFORMATION mbi{};
		unsigned char* addr = nullptr;
		while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
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
	}

	void proc_inspect(DWORD pid) {
		print_process_name_and_id(pid);

		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
			FALSE,
			pid);

		if (!hProcess) {
			std::cout << "Error while opening process" << std::endl;
			return;
		}

		HMODULE hMod;
		DWORD cbNeeded;
		wchar_t baseName[512];

		if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
			GetModuleBaseNameW(hProcess, hMod, baseName, 512);
			std::wcout << baseName << std::endl;
		}

		enumerate_modules(hProcess);

		// For feature 1
		// Get module information => Base address + size for all modules
		// Put that in enumerate_modules

		// Feature 2: Memory region viewer (enumerate_mem...)

	}
}
