#pragma once

#include <Windows.h>

namespace PT::ModuleResolver {
	HMODULE get_local_module(const wchar_t* module_name);

	FARPROC resolve_local_function(const wchar_t* module_name, const char* function_name);
}
