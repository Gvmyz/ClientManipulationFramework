// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

// WINAPI = __stdcall. Required by LPTHREAD_START_ROUTINE (CreateRemoteThread
// signature) on x86. But on x86 the __stdcall export gets name-decorated as
// `_RunTest@4` (underscore prefix, @N byte-count suffix), so a plain
// GetProcAddress(mod, "RunTest") returns NULL. The alias pragma below tells
// the linker to also expose the undecorated name. On x64 no decoration
// happens (one unified calling convention) so no alias is needed.
extern "C" __declspec(dllexport)
DWORD WINAPI RunTest(LPVOID) {
	MessageBox(NULL, L"[TestDll] RunTest() called!", L"[TestDll] RunTest() called!", NULL);
	// OutputDebugStringW(L"[TestDll] RunTest() called!\n");
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
			MessageBox(NULL, L"[TestDll] DLL Loaded...", L"[TestDll] DLL Loaded...", NULL);
			OutputDebugStringW(L"[TestDll] DLL Loaded...\n");
			break;
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
	}
	return TRUE;
}

