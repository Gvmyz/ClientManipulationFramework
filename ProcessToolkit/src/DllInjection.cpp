#include "DllInjection.h"

#include <cstdint>

#include "ProcessMemory.h"
#include "ProcessThread.h"
#include "ModuleResolver.h"

namespace PT::DllInjection {
	std::optional<DWORD> inject_dll_loadlibrary(const WinHandle& process, const std::wstring_view dll_path) {
		if (!process || dll_path.empty()) return std::nullopt;

		const SIZE_T path_size = (dll_path.size() + 1) * sizeof(wchar_t);

		void* remote_path = PT::ProcessMemory::remote_alloc(process, path_size, PAGE_READWRITE);

		if (!remote_path) return std::nullopt;

		if (!PT::ProcessMemory::remote_write(process, remote_path, dll_path.data(), path_size)) {
			PT::ProcessMemory::remote_free(process, remote_path);
			return std::nullopt;
		}

		auto load_library = reinterpret_cast<LPTHREAD_START_ROUTINE>(PT::ModuleResolver::resolve_local_function(L"kernel32.dll", "LoadLibraryW"));

		if (!load_library) {
			PT::ProcessMemory::remote_free(process, remote_path);
			return std::nullopt;
		}

		auto thread = PT::ProcessThread::create_remote_thread(process, load_library, remote_path);

		if (!thread) {
			PT::ProcessMemory::remote_free(process, remote_path);
			return std::nullopt;
		}

		if (PT::ProcessThread::wait_for_thread(thread) != WAIT_OBJECT_0) {
			PT::ProcessMemory::remote_free(process, remote_path);
			return std::nullopt;
		}

		DWORD exit_code = 0;
		if (!PT::ProcessThread::get_thread_exit_code(thread, exit_code) || exit_code == 0) {
			PT::ProcessMemory::remote_free(process, remote_path);
			return std::nullopt;
		}

		PT::ProcessMemory::remote_free(process, remote_path);

		if (exit_code == 0) return std::nullopt; // LoadLibraryW returns NULL on failure

		return exit_code; // The exit code is the base address of the loaded module in the target process
	}

	bool call_exported_function(const WinHandle& process, const std::wstring_view& local_dll_path, const std::uintptr_t remote_module_base, const std::string_view& function_name) {
		if (!process || local_dll_path.empty() || function_name.empty() || remote_module_base == 0) return false;

		HMODULE local_module = LoadLibraryW(std::wstring(local_dll_path).c_str());
		if (!local_module) return false;

		FARPROC local_func = GetProcAddress(local_module, std::string(function_name.data()).c_str());
		if (!local_func) {
			FreeLibrary(local_module);
			return false;
		}

		auto func_offset = reinterpret_cast<std::uintptr_t>(local_func) - reinterpret_cast<std::uintptr_t>(local_module);
		auto remote_func_addr = reinterpret_cast<LPTHREAD_START_ROUTINE>(remote_module_base + func_offset);

		auto thread = PT::ProcessThread::create_remote_thread(process, remote_func_addr, nullptr);
		if (!thread) {
			FreeLibrary(local_module);
			return false;
		}

		bool ok = PT::ProcessThread::wait_for_thread(thread) == WAIT_OBJECT_0;

		FreeLibrary(local_module);
		return ok;
	}
}

