#include <windows.h>
#include <stdio.h>
#include <string>
#include <psapi.h>
#include <vector>
#include <evntrace.h>

#pragma comment(lib, "advapi32.lib")

#pragma comment(lib, "psapi.lib")

SERVICE_STATUS          g_status{};
SERVICE_STATUS_HANDLE   g_statusHandle{};
HANDLE                  g_stopEvent = nullptr;
HANDLE                  g_childProcess = nullptr;
std::wstring            g_sessionName;

static void Log(const wchar_t* fmt, ...) {
    FILE* f = nullptr;
    if (_wfopen_s(&f, L"C:\\elam\\pplrunner.log", L"a, ccs=UTF-8") || !f) return;
    va_list ap; va_start(ap, fmt); vfwprintf(f, fmt, ap); va_end(ap);
    fwprintf(f, L"\n"); fclose(f);
}

static void ReportStatus(DWORD state, DWORD exitCode = NO_ERROR) {
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwWin32ExitCode = exitCode;
    g_status.dwControlsAccepted = (state == SERVICE_RUNNING) ? SERVICE_ACCEPT_STOP : 0;
    SetServiceStatus(g_statusHandle, &g_status);
}

static DWORD WINAPI HandlerEx(DWORD ctrl, DWORD, LPVOID, LPVOID) {
    if (ctrl == SERVICE_CONTROL_STOP) { ReportStatus(SERVICE_STOP_PENDING); SetEvent(g_stopEvent); }
    return NO_ERROR;
}

static std::wstring ReadConfigCommandLine() {
    HANDLE f = CreateFileW(L"C:\\elam\\runner.cfg", GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) { Log(L"runner.cfg open failed %lu", GetLastError()); return L""; }
    char buf[2048]; DWORD read = 0;
    ReadFile(f, buf, sizeof(buf) - 1, &read, nullptr); CloseHandle(f);
    std::string s(buf, read);
    while (!s.empty() && (s.back() == '\r' || s.back() == '\n' || s.back() == ' ' || s.back() == '\0')) s.pop_back();
    int wlen = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w(wlen, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], wlen);
    if (!w.empty() && w.back() == L'\0') w.pop_back();
    return w;
}

// Launch a child process with PPL protection (protected process light)
static bool LaunchProtectedChild(std::wstring cmdLine) {
    STARTUPINFOEXW si{}; si.StartupInfo.cb = sizeof(si);
    SIZE_T attrSize = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attrSize);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
    if (!si.lpAttributeList) return false;
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrSize);
    DWORD level = PROTECTION_LEVEL_SAME;
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL,
        &level, sizeof(level), nullptr, nullptr);
    cmdLine.push_back(L'\0');
    PROCESS_INFORMATION pi{};
    BOOL ok = CreateProcessW(nullptr, &cmdLine[0], nullptr, nullptr, FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS,
        nullptr, nullptr, (LPSTARTUPINFOW)&si, &pi);
    DeleteProcThreadAttributeList(si.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
    if (!ok) { Log(L"CreateProcess failed %lu", GetLastError()); return false; }
    Log(L"child launched pid %lu", pi.dwProcessId);
    g_childProcess = pi.hProcess; CloseHandle(pi.hThread);
    return true;
}

static std::wstring ExtractSessionName(const std::wstring& cmd) {
    const std::wstring key = L"--session";
    size_t p = cmd.find(key);
    if (p == std::wstring::npos) return L"";
    p += key.size();
    while (p < cmd.size() && iswspace(cmd[p])) ++p;
    size_t end = p;
    while (end < cmd.size() && !iswspace(cmd[end])) ++end;
    return cmd.substr(p, end - p);
}

static void StopEtwSession(const std::wstring& name) {
    if (name.empty()) return;
    size_t size = sizeof(EVENT_TRACE_PROPERTIES) + (name.size() + 1) * sizeof(wchar_t);
    std::vector<BYTE> buf(size, 0);
    auto props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buf.data());
    props->Wnode.BufferSize = (ULONG)size;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    ULONG s = ControlTraceW(0, name.c_str(), props, EVENT_TRACE_CONTROL_STOP);
    Log(L"ControlTrace stop '%ls' -> %lu", name.c_str(), s);
}

static void WINAPI ServiceMain(DWORD, LPWSTR*) {
    g_statusHandle = RegisterServiceCtrlHandlerExW(L"PPLRunner", HandlerEx, nullptr);
    if (!g_statusHandle) return;
    ReportStatus(SERVICE_START_PENDING);
    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

    DeleteFileW(L"C:\\elam\\stop.flag");   // clear any stale stop request

    // kill any leftover child from a previous run that may still hold the output file
    {
        DWORD pids[1024], cb = 0;
        if (EnumProcesses(pids, sizeof(pids), &cb)) {
            for (DWORD i = 0; i < cb / sizeof(DWORD); ++i) {
                HANDLE p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, FALSE, pids[i]);
                if (!p) continue;
                wchar_t name[MAX_PATH]; DWORD n = MAX_PATH;
                if (QueryFullProcessImageNameW(p, 0, name, &n)) {
                    if (wcsstr(name, L"\\Telemetry.exe")) TerminateProcess(p, 0);
                }
                CloseHandle(p);
            }
        }
    }

    std::wstring cmd = ReadConfigCommandLine();
    g_sessionName = ExtractSessionName(cmd);
    if (!cmd.empty()) { Log(L"launching: %ls", cmd.c_str()); LaunchProtectedChild(cmd); }

    ReportStatus(SERVICE_RUNNING);
    for (;;) {
        DWORD n = g_childProcess ? 2 : 1;
        HANDLE waits[2] = { g_stopEvent, g_childProcess ? g_childProcess : g_stopEvent };
        DWORD r = WaitForMultipleObjects(n, waits, FALSE, 1000);   // 1s poll
        if (r == WAIT_OBJECT_0) break;                              // SCM stop (shutdown)
        if (g_childProcess && r == WAIT_OBJECT_0 + 1) {             // child exited on its own
            CloseHandle(g_childProcess); g_childProcess = nullptr; break;
        }
        if (GetFileAttributesW(L"C:\\elam\\stop.flag") != INVALID_FILE_ATTRIBUTES) break;
    }
	// Graceful Block: Stop the child process and ETW session
    ReportStatus(SERVICE_STOP_PENDING);
    if (g_childProcess) {
        StopEtwSession(g_sessionName);                                  // make ProcessTrace return + flush
        if (WaitForSingleObject(g_childProcess, 5000) != WAIT_OBJECT_0) {
            Log(L"child did not exit in time, terminating");
            TerminateProcess(g_childProcess, 0);                        // fallback only
        }
        else {
            Log(L"child exited gracefully");
        }
        CloseHandle(g_childProcess);
        g_childProcess = nullptr;
    }
    ReportStatus(SERVICE_STOPPED);

    ReportStatus(SERVICE_STOPPED);
}

static int DoInstall() {
    wchar_t path[MAX_PATH]; GetModuleFileNameW(nullptr, path, MAX_PATH);
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) { wprintf(L"OpenSCManager failed %lu\n", GetLastError()); return 1; }
    SC_HANDLE svc = OpenServiceW(scm, L"PPLRunner", SERVICE_ALL_ACCESS);
    if (!svc) {
        svc = CreateServiceW(scm, L"PPLRunner", L"PPLRunner", SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
            path, nullptr, nullptr, nullptr, nullptr, nullptr);
        if (!svc) { wprintf(L"CreateService failed %lu\n", GetLastError()); return 1; }
    }
	// Make it protected (PPL) so that it can launch protected child processes
    SERVICE_LAUNCH_PROTECTED_INFO info{};
    info.dwLaunchProtected = SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT;
    if (!ChangeServiceConfig2W(svc, SERVICE_CONFIG_LAUNCH_PROTECTED, &info)) {
        wprintf(L"ChangeServiceConfig2 failed %lu\n", GetLastError()); return 1;
    }
    wprintf(L"PPLRunner installed and set to ANTIMALWARE_LIGHT\n");
    CloseServiceHandle(svc); CloseServiceHandle(scm); return 0;
}

int wmain(int argc, wchar_t** argv) {
    if (argc >= 2 && wcscmp(argv[1], L"--install") == 0) return DoInstall();
    SERVICE_TABLE_ENTRYW table[] = { { const_cast<LPWSTR>(L"PPLRunner"), ServiceMain }, { nullptr, nullptr } };
    StartServiceCtrlDispatcherW(table);
    return 0;
}