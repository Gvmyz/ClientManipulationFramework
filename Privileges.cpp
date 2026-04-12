#include "Privileges.h"
#include <windows.h>	

namespace PT {
	namespace Privileges {
		bool enable_debug_privilege(bool enable) {
			HANDLE token = nullptr;
			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
				return false;
			}
			LUID luid{};
			if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid)) {
				CloseHandle(token);
				return false;
			}
			TOKEN_PRIVILEGES tp{};
			tp.PrivilegeCount = 1;
			tp.Privileges[0].Luid = luid;
			tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;
			AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
			bool ok = (GetLastError() == ERROR_SUCCESS);
			CloseHandle(token);
			return ok;
		}
	}
}
