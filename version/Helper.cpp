#include "Helper.h"
#include <Windows.h>
#include <tlhelp32.h>
#include <string>

void decrypt(unsigned char* data, long dataLen, unsigned char* key, long keyLen, unsigned char* result) {
	unsigned char T[256];
	unsigned char S[256];
	unsigned char  tmp;
	int j = 0, t = 0, i = 0;


	for (int i = 0; i < 256; i++) {
		S[i] = i;
		T[i] = key[i % keyLen];
	}

	for (int i = 0; i < 256; i++) {
		j = (j + S[i] + T[i]) % 256;
		tmp = S[j];
		S[j] = S[i];
		S[i] = tmp;
	}
	j = 0;
	for (int x = 0; x < dataLen; x++) {
		i = (i + 1) % 256;
		j = (j + S[i]) % 256;

		tmp = S[j];
		S[j] = S[i];
		S[i] = tmp;

		t = (S[i] + S[j]) % 256;

		result[x] = data[x] ^ S[t];
	}
}

BOOL IsWow64(HANDLE pHandle)
{
	BOOL isWow64 = FALSE;

	typedef BOOL(WINAPI *PFNIsWow64Process) (HANDLE, PBOOL);
	PFNIsWow64Process _FNIsWow64Process;
	_FNIsWow64Process = (PFNIsWow64Process)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "IsWow64Process");

	if (NULL != _FNIsWow64Process) {
		if (!_FNIsWow64Process(pHandle, &isWow64)) {}
	}
	return isWow64;
}

DWORD FindPID(const char* procname)
{
	// Dynamically resolve some functions
	HMODULE kernel32 = GetModuleHandleA("Kernel32.dll");

    using CreateToolhelp32SnapshotPrototype = HANDLE(WINAPI *)(DWORD, DWORD);
    CreateToolhelp32SnapshotPrototype CreateToolhelp32Snapshot = (CreateToolhelp32SnapshotPrototype)GetProcAddress(kernel32, "CreateToolhelp32Snapshot");
    
    using Process32FirstPrototype = BOOL(WINAPI *)(HANDLE, LPPROCESSENTRY32);
    Process32FirstPrototype Process32First = (Process32FirstPrototype)GetProcAddress(kernel32, "Process32First");
    
    using Process32NextPrototype = BOOL(WINAPI *)(HANDLE, LPPROCESSENTRY32);
    Process32NextPrototype Process32Next = (Process32NextPrototype)GetProcAddress(kernel32, "Process32Next");
    
    // Init some important local variables
    HANDLE hProcSnap;
    PROCESSENTRY32 pe32;
    DWORD pid = 0;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Find the PID now by enumerating a snapshot of all the running processes
    hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcSnap)
        return 0;

    if (!Process32First(hProcSnap, &pe32)) {
        CloseHandle(hProcSnap);
        return 0;
    }

    while (Process32Next(hProcSnap, &pe32)) {
        if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    }
	    
	// Cleanup
	CloseHandle(hProcSnap);

	return pid;
}
