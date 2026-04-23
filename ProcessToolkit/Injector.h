#pragma once

#include <string_view>

#include "WinHandle.h"
#include <optional>


namespace PT {
	namespace Injector {
		std::optional<DWORD> inject_dll(const WinHandle& process, const std::wstring_view& dll_path);
		bool unload_dll(const WinHandle& process, const std::wstring_view& dll_path);

		// Possibly return the result of the function call in the target process (e.g. by writing to a shared memory region or using an IPC mechanism)
		bool call_injected_function(const WinHandle& process, const std::wstring_view& dll_name, const std::uintptr_t dll_base, const std::string_view& function_name);

		std::optional<std::uintptr_t> local_func_offset(const std::wstring_view& dll_name, const std::string_view& function_name);
		std::optional<HMODULE> local_inject(const std::wstring_view& dll_path);
	}
}