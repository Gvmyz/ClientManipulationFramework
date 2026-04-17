#include "Injector.h"

#include <windows.h>
#include <string_view>

#include "WinHandle.h"
#include "Memory.h"

namespace PT {
	namespace Injector {
		std::optional<DWORD> inject_dll(const WinHandle& process, const std::wstring_view& dll_path) {
			if (!process) return std::nullopt;

			auto dll_base = PT::Memory::allocate_and_write(process, dll_path.data(), (dll_path.size() + 1) * sizeof(wchar_t));
			if (!dll_base) return std::nullopt;
			//LoadLibraryW(L"C:\\Users\\alexs\\TU_WIEN\\THESIS\\Projects\\ProcessToolkit\\x64\\Release\\TestDll.dll");


			//Get the address of LoadLibraryW in kernel32.dll
			HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
			if (!hKernel32) {
				//PT::Memory::free_memory(process, *dll_base, 0, MEM_RELEASE);
				return std::nullopt;
			}

			FARPROC loadLibraryAddr = GetProcAddress(hKernel32, "LoadLibraryW");
			if (!loadLibraryAddr) {
				// PT::Memory::free_memory(process, *dll_base, 0, MEM_RELEASE);
				return std::nullopt;
			}

			auto hThread = PT::Memory::create_thread(process, reinterpret_cast<std::uintptr_t>(loadLibraryAddr), (void*)*dll_base);
			if (!hThread) {
				//PT::Memory::free_memory(process, *dll_base, 0, MEM_RELEASE);
				return std::nullopt;
			}

			auto res = PT::Memory::wait_for_thread_exit_code(*hThread);
			if (!res) return std::nullopt;
			return *res;
		}

		bool unload_dll(const WinHandle& process, const DWORD hModule) {
			if (!process) return false;
			// Get the base address of the loaded DLL in the target process
			if (!hModule) return false;
			// Get the address of FreeLibrary in kernel32.dll
			HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
			if (!hKernel32) {
				return false;
			}
			FARPROC freeLibraryAddr = GetProcAddress(hKernel32, "FreeLibrary");
			if (!freeLibraryAddr) {
				return false;
			}
			auto hThread = PT::Memory::create_thread(process, reinterpret_cast<std::uintptr_t>(freeLibraryAddr), (void*)hModule);
			if (!hThread) {
				return false;
			}
			WaitForSingleObject((*hThread).get(), INFINITE);
			return true;
		}

		// Get possibly return value
		bool call_injected_function(const WinHandle& process, const std::wstring_view& dll_name, const std::uintptr_t dll_base, const std::string_view& function_name) {
			if (!process) return false;
			// Get the address of the function in the injected DLL
			auto func_offset = local_func_offset(dll_name, function_name);
			if (!func_offset) return false;
			std::uintptr_t func_address = (*func_offset) + dll_base;
			auto hThread = PT::Memory::create_thread(process, func_address);
			if (!hThread) {
				return false;
			}
			WaitForSingleObject((*hThread).get(), INFINITE);
			return true;
		}

		std::optional<std::uintptr_t> local_func_offset(const std::wstring_view& dll_name, const std::string_view& function_name) {
			HMODULE hModule = GetModuleHandleW(dll_name.data());
			if (!hModule) return std::nullopt;
			FARPROC funcAddr = GetProcAddress(hModule, function_name.data());
			if (!funcAddr) return std::nullopt;
			return reinterpret_cast<std::uintptr_t>(funcAddr) - reinterpret_cast<std::uintptr_t>(hModule);
		}

		std::optional<HMODULE> local_inject(const std::wstring_view& dll_path) {
			HMODULE hModule = LoadLibraryW(dll_path.data());
			if (!hModule) return std::nullopt;
			return hModule;
		}
	}
}
