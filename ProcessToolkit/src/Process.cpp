#include "Process.h"

#include <Windows.h>
#include <string>
#include <vector>
#include <optional>
#include <iostream>
#include "Psapi.h"
#include <array>

#include "WinHandle.h"


namespace PT {
	namespace Process {
		std::vector<DWORD> list_processes() {
			std::vector<DWORD> pids;
			std::array<DWORD, 1024> buffer{};
			DWORD bytesReturned;
			if (!EnumProcesses(buffer.data(), static_cast<DWORD>(buffer.size() * sizeof(DWORD)), &bytesReturned)) {
				return {};
			}
			size_t count = bytesReturned / sizeof(DWORD);
			pids.assign(buffer.begin(), buffer.begin() + count);
			return pids;
		}

		std::optional<std::wstring> get_image_path(DWORD pid) {
			WinHandle process{ OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid) };
			if (!process) return std::nullopt;

			std::array<wchar_t, MAX_PATH> path{};
			DWORD size = MAX_PATH;
			if (QueryFullProcessImageNameW(process.get(), 0, path.data(), &size)) {
				return std::wstring(path.data(), size);
			}
			return std::nullopt;
		}

		WinHandle open_process(DWORD pid, DWORD desired_access) {
			HANDLE hProcess = OpenProcess(desired_access, FALSE, pid);
			if (!hProcess) return WinHandle{};
			return WinHandle(hProcess);
		}
	}
}
