#include <Windows.h>
#include <stdio.h>
#include "packer_crypto.h"
#include "packer_PE.h"


int main(int argc, char **argv) {
	HRSRC hRsrc;
	HGLOBAL hGlob;
	DWORD dwRsrcSize;
	DWORD dwBytesWritten;
	LPBYTE lpStubBuffer;
	LPBYTE lpCipher;
	CHAR szBFileName[MAX_PATH];
	BYTE bKey;

	LPBYTE lpFileBuffer;
	DWORD dwBytesRead;
	DWORD dwFileSize;
	HANDLE hFile;
	HANDLE hUpdate;
	char szInputFile[MAX_PATH];

	printf("\n");
	printf("[+] Demo Packer - BSides London 2013\n");
	printf("\n");

	if(argc != 2) {
		printf("[-] Usage: %s <executable>\n", argv[0]);
		return 1;
	}

	memset(szInputFile, 0, MAX_PATH);
		
	strncpy_s(szInputFile, MAX_PATH, argv[1], strlen(argv[1]));

	hFile = CreateFileA(szInputFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	if(hFile == INVALID_HANDLE_VALUE) {
		printf("[-] Cannot open file: %s. (Error %d)\n", szInputFile, GetLastError());
		return 1;
	}
	dwFileSize = GetFileSize(hFile, NULL);
	if(dwFileSize == INVALID_FILE_SIZE) {
		printf("[-] Cannot get file size for: %s. (Error %d)\n", szInputFile, GetLastError() );
		return 1;
	}
	lpFileBuffer = (LPBYTE) malloc(dwFileSize * sizeof(BYTE));
	if(lpFileBuffer == NULL) {
		printf("[-] Unable to allocate enough memory to process file.\n");
		return 1;
	}

	ReadFile(hFile, lpFileBuffer, dwFileSize, &dwBytesRead, NULL);
	CloseHandle(hFile);

	if(!ValidatePE(lpFileBuffer)) {
		printf("[-] File: %s is not a Portable Executable file.\n", szInputFile);
		return 1;
	}

	strncpy_s(szBFileName, MAX_PATH, szInputFile, strlen(szInputFile));
	strncat_s(szBFileName, MAX_PATH, ".bak", 4);
	if(CopyFileA(szInputFile, szBFileName, FALSE) == 0) {
		printf("[-] Could not copy original file to backup file (%d)\n", GetLastError());
		return 1;
	}
	printf("[+] Backed up %s to %s\n", szInputFile, szBFileName);

	hRsrc = FindResourceA(NULL, MAKEINTRESOURCEA(106), "STUB");
	if(hRsrc == NULL) {
		printf("[-] Could not find STUB resouce (%d)\n", GetLastError());
		return 1;
	}
	
	dwRsrcSize = SizeofResource(NULL, hRsrc);
	hGlob = LoadResource(NULL, hRsrc);
	if(hGlob == NULL) {
		printf("[-] Could not load STUB resource (%d)\n", GetLastError());
		return 1;
	}
	
	lpStubBuffer = (LPBYTE) LockResource(hGlob);
	if(lpStubBuffer == NULL) {
		printf("[-] Could not lock STUB resource (%d)\n",GetLastError());
		return 1;
	}

	bKey = GenerateKey();
	lpCipher = (LPBYTE) malloc(dwFileSize*sizeof(BYTE));
	Encrypt(&bKey, lpFileBuffer, lpCipher, dwFileSize);

	printf("[+] Adding the payload as a resource to the stub...");
	hFile = CreateFileA(szInputFile, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL);
	if(hFile == INVALID_HANDLE_VALUE) {
		printf("[-] Could not create new file to write output (%d)\n", GetLastError());
		return 1;
	}
	if(WriteFile(hFile, lpStubBuffer, dwRsrcSize, &dwBytesWritten, NULL) == 0) {
		CloseHandle(hFile);
		printf("[-] Could not write to new file (%d)\n", GetLastError());
		return 1;
	}
	CloseHandle(hFile);
	
	hUpdate = BeginUpdateResourceA(szInputFile, FALSE);
	if(hUpdate == NULL)	{
			printf("[-] Could not update resources (%d)\n", GetLastError());
			return 1;
	}
	if(UpdateResource(hUpdate, RT_RCDATA, MAKEINTRESOURCE(150), MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), lpCipher, dwFileSize) == FALSE) {
			printf("[-] Could not add the resource (%d)\n", GetLastError());
			return 1;
	}
	if(EndUpdateResourceA(hUpdate, FALSE) == FALSE) {
			printf("[-] Could not end the update resources  process (%d)\n", GetLastError());
			return 1;
	}
	printf("done\n");
	printf("[+] Process completed\n");

	return 0;
}


