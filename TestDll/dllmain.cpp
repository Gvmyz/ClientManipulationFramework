// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <cstdio>

// Independent delivery evidence for the runner. This avoids invoking RunTest
// through a second remote thread just to verify a thread-hijack experiment.
static HANDLE g_attach_event = nullptr;

// WINAPI = __stdcall. Required by LPTHREAD_START_ROUTINE (CreateRemoteThread
// signature) on x86. But on x86 the __stdcall export gets name-decorated as
// `_RunTest@4` (underscore prefix, @N byte-count suffix), so a plain
// GetProcAddress(mod, "RunTest") returns NULL. The alias pragma below tells
// the linker to also expose the undecorated name. On x64 no decoration
// happens (one unified calling convention) so no alias is needed.
//
// Uses OutputDebugStringW instead of MessageBox so campaign runs are
// non-blocking. MessageBox from DllMain/RunTest is also a known bad practice
// (potential loader-lock deadlock) and causes DWM/system-services to poll the
// dialog's window state, inflating threatint_cross_process_count by ~3000×.
// Attach a debugger or run DebugView to see the "TestDll" strings.
extern "C" __declspec(dllexport)
DWORD WINAPI RunTest(LPVOID) {
	OutputDebugStringW(L"[TestDll] RunTest() called!\n");
	return 0;
}

#ifndef _WIN64
#pragma comment(linker, "/EXPORT:RunTest=_RunTest@4")
#endif

BOOL APIENTRY DllMain(HMODULE hModule,
					  DWORD  ul_reason_for_call,
					  LPVOID lpReserved
) {
	switch (ul_reason_for_call) {
		case DLL_PROCESS_ATTACH:
			DisableThreadLibraryCalls(hModule);
            {
                wchar_t name[96]{};
                swprintf_s(name, L"Local\\CMF_TestDll_Attached_%lu", GetCurrentProcessId());
                g_attach_event = CreateEventW(nullptr, TRUE, TRUE, name);
            }
			OutputDebugStringW(L"[TestDll] DLL Loaded...\n");
			break;
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
            if (ul_reason_for_call == DLL_PROCESS_DETACH && g_attach_event) {
                CloseHandle(g_attach_event);
                g_attach_event = nullptr;
            }
			break;
	}
	return TRUE;
}

