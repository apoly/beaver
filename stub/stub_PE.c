#include "stub_PE.h"

PIMAGE_DOS_HEADER pidh = NULL;
PIMAGE_NT_HEADERS pinh = NULL;
PIMAGE_SECTION_HEADER pish = NULL;

CHAR szProcessName[MAX_PATH] = { 0 };
LPBYTE lpBuffer = NULL;
LPBYTE lpCopy = NULL;
STARTUPINFO si = { 0 };
PROCESS_INFORMATION pi = { 0 };
CONTEXT ctx = { 0 };

BOOL Validate(LPBYTE lpBuffer) {
	pidh = (PIMAGE_DOS_HEADER) &lpBuffer[0];
	if(pidh->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;
	pinh = (PIMAGE_NT_HEADERS)&lpBuffer[pidh->e_lfanew];
	if(pinh->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;
	return TRUE;
}

