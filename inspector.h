#pragma once

#include "Windows.h"

namespace inspector {
	void hello();

	void print_process_name_and_id(DWORD processID);

	void enumerate_modules(HANDLE process);

	void proc_inspect(int pid);
}
