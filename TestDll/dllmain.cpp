// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

extern "C" __declspec(dllexport)
DWORD WINAPI RunTest(LPVOID) {
	MessageBox(NULL, L"[TestDll] RunTest() called!", L"[TestDll] RunTest() called!", NULL);
	// OutputDebugStringW(L"[TestDll] RunTest() called!\n");
	return 0;
}

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

