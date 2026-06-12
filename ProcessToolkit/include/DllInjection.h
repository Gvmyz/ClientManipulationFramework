#pragma once

#include <Windows.h>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "WinHandle.h"

namespace PT::DllInjection {
	std::optional<DWORD> inject_dll_loadlibrary(const WinHandle& process, const std::wstring_view dll_path);

	// Returns the remote image base on success.
	// Resolves imports, applies base relocations, and calls DllMain via a small loader stub.
	std::optional<std::uintptr_t> inject_dll_manualmap(const WinHandle& process, const std::wstring_view dll_path);

	// Hijacks an existing thread in the target process to call LoadLibraryW(dll_path)
	// thread resumes its prior work transparently after the DLL is loaded.
	std::optional<DWORD> inject_dll_threadhijack(const WinHandle& process, const std::wstring_view dll_path);

	bool call_exported_function(const WinHandle& process, const std::wstring_view& local_dll_path, const std::uintptr_t remote_module_base, const std::string_view& function_name);
}
