#ifndef __STUB_PE_
#define __STUB_PE_

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

#define UPPER	2000
#define LOWER	15

extern PIMAGE_DOS_HEADER pidh;
extern PIMAGE_NT_HEADERS pinh;
extern PIMAGE_SECTION_HEADER pish;
extern CHAR szProcessName[MAX_PATH];

extern LPBYTE lpBuffer;
extern LPBYTE lpCopy;
extern STARTUPINFO si;
extern PROCESS_INFORMATION pi;
extern CONTEXT ctx;

BOOL Validate(LPBYTE lpBuffer);

#endif