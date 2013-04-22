#include "packer_PE.h"

/* checks header signatures to validate if byte array is a PE */
BOOL ValidatePE(LPBYTE lpBytes) {
	PIMAGE_DOS_HEADER pidh;
	PIMAGE_NT_HEADERS pinh;
	pidh = (PIMAGE_DOS_HEADER) lpBytes;
	printf("[+] Validating PE file format by checking header signatures...\n");
	if(pidh->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("\t[-] Error: MZ signature not found.\n");
		return FALSE;
	}
	printf("\t[+] MZ signature found.\n");
	pinh = (PIMAGE_NT_HEADERS) &lpBytes[pidh->e_lfanew];
	if(pinh->Signature != IMAGE_NT_SIGNATURE) {
		printf("\t[-] Error: NT signature not found.\n");
		return FALSE;
	}
	printf("\t[+] NT signature found.\n");
	return TRUE; 
}