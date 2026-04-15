#include "Injector.h"

#include <windows.h>
#include <string_view>

#include "WinHandle.h"
#include "Memory.h"

namespace PT {
	namespace Injector {
		bool inject_dll(const WinHandle& process, const std::wstring_view& dll_path) {
			if (!process) return false;

			auto dll_base = PT::Memory::allocate_and_write(process, dll_path.data(), (dll_path.size() + 1) * sizeof(wchar_t));
			if (!dll_base) return false;

			//LoadLibraryW(L"C:\\Users\\alexs\\TU_WIEN\\THESIS\\Projects\\ProcessToolkit\\x64\\Release\\TestDll.dll");


			//Get the address of LoadLibraryW in kernel32.dll
			HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
			if (!hKernel32) {
				//PT::Memory::free_memory(process, *dll_base, 0, MEM_RELEASE);
				return false;
			}

			FARPROC loadLibraryAddr = GetProcAddress(hKernel32, "LoadLibraryW");
			if (!loadLibraryAddr) {
				//PT::Memory::free_memory(process, *dll_base, 0, MEM_RELEASE);
				return false;
			}

			auto hThread = PT::Memory::create_thread(process, reinterpret_cast<std::uintptr_t>(loadLibraryAddr), (void*)*dll_base);
			if (!hThread) {
				//PT::Memory::free_memory(process, *dll_base, 0, MEM_RELEASE);
				return false;
			}



			// Create a remote thread that calls LoadLibraryW with the DLL path
			//HANDLE hThread = CreateRemoteThread(process.get(), nullptr, 0,
			//									reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibraryAddr),
			//									remote_mem, 0, nullptr);
			//if (!hThread) {
			//	VirtualFreeEx(process.get(), remote_mem, 0, MEM_RELEASE);
			//	return false;
			//}
			// Wait for the remote thread to finish
			WaitForSingleObject((*hThread).get(), INFINITE);
			//VirtualFreeEx(process.get(), remote_mem, 0, MEM_RELEASE); // Need to free
			return true;
		}
	}
}
