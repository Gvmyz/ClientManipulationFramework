#pragma once

#include <string_view>

#include "WinHandle.h"


namespace PT {
	namespace Injector {
		bool inject_dll(const WinHandle& process, const std::wstring_view& dll_path);
	}
}