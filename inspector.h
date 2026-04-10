#pragma once

#include "Windows.h"
#include <vector>

namespace inspector {
	void hello();

	std::vector<DWORD> enum_processes();

	void print_process_name_and_id(DWORD processID);

	void enumerate_modules(HANDLE process);

	void proc_inspect(int pid);
}
