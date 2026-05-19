#pragma once

#include <Windows.h>
#include <optional>
#include <string>
#include <string_view>

#include "WinHandle.h"

namespace PT::DllInjection {
	std::optional<DWORD> inject_dll_loadlibrary(const WinHandle& process, const std::wstring_view dll_path);

	bool call_exported_function(const WinHandle& process, const std::wstring_view& local_dll_path, const std::uintptr_t remote_module_base, const std::string_view& function_name);
}
