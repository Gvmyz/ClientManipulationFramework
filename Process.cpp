#include "Process.h"

#include <Windows.h>
#include <string>

struct ProcessInfo {
	DWORD pid;
	std::wstring path;
	std::wstring name;
};

