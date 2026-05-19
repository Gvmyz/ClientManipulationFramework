#include "ModuleResolver.h"

namespace PT::ModuleResolver {
	HMODULE get_local_module(const wchar_t* module_name) {
		HMODULE module = GetModuleHandleW(module_name);

		if (!module) {
			// Try loading the module if it's not already loaded
			module = LoadLibraryW(module_name);
		}
		return module;
	}

	FARPROC resolve_local_function(const wchar_t* module_name, const char* function_name) {
		HMODULE module = get_local_module(module_name);
		if (!module) return nullptr;
		return GetProcAddress(module, function_name);
	}
}
