#pragma once

#include <string>
#include <Windows.h>
#include <vector>
#include <optional>

#include "WinHandle.h"

namespace PT {
	namespace Process {
		std::vector<DWORD> list_processes();
		std::optional<std::wstring> get_image_path(DWORD pid);

		// Open with safe defaults (query + vm read)
		WinHandle open_process(DWORD pid, DWORD desired_access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
	}
}


