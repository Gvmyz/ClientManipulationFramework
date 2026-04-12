#pragma once

#include "Windows.h"
#include <vector>
#include <optional>

#include "WinHandle.h"

namespace PT {
	void hello();

	std::vector<DWORD> get_processes();

	WinHandle open_process(DWORD pid);

	std::optional<std::wstring> get_process_image_path(DWORD processId);

	void enumerate_modules(HANDLE process);

	std::vector<MEMORY_BASIC_INFORMATION> get_memory_infos(HANDLE hProcess);

	void proc_inspect(int pid);
}
