#include "packer_crypto.h"
#include <TlHelp32.h>
#include <WinCrypt.h>
#include <stdio.h>


LPBYTE Expand(LPBYTE bKey) {
	LPBYTE lpExpKey;
	unsigned n;
	int i;
	lpExpKey = (LPBYTE) malloc(MAX_PATH*sizeof(BYTE));
	ZeroMemory(lpExpKey, MAX_PATH*sizeof(BYTE));
	for(n = 256, i = 0; n > 0; n /= 2, i++) {
		if (*bKey & n) lpExpKey[i] = 0x31;
		else lpExpKey[i] = 0x30;
	}
	lpExpKey[i] = 0x00;
	return lpExpKey;
}

/*
 * Simple, native encryption using RC4, inspired from one of Howard's 
 * old books.
 *
 * In a nutshell: Acquire the CSP handle, create an empty hash, put 
 * the hash of the key in it, derive the crypto key from it. Note
 * (from Howard) the key also stores the algorithm in order to
 * perform the encryption.
 *
 * Return: TRUE if completed successfully, FALSE otherwise.
 */
BOOL Encrypt(LPBYTE bKey, LPBYTE bPlaintext, LPBYTE bCipherText, DWORD dwHowMuch) {
	
	HCRYPTPROV hProv;
	HCRYPTKEY  hKey;
	HCRYPTHASH hHash;
	LPBYTE lpExpKey;
	DWORD dwBuff = dwHowMuch;
	CopyMemory(bCipherText, bPlaintext, dwHowMuch);

	lpExpKey = Expand(bKey);

	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, 
								CRYPT_VERIFYCONTEXT))
		return FALSE;
	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
		return FALSE;
	if (!CryptHashData(hHash, lpExpKey, strlen((char *) lpExpKey), 0))
		return FALSE;
	if (!CryptDeriveKey(hProv, CALG_RC4, hHash, 
						CRYPT_EXPORTABLE, 
						&hKey))
		return FALSE;
	if (!CryptEncrypt(hKey, 0, TRUE, 0, 
						bCipherText, 
						&dwBuff, 
						dwHowMuch))
		return FALSE;

	if (hKey)  CryptDestroyKey(hKey);
	if (hHash) CryptDestroyHash(hHash);
	if (hProv) CryptReleaseContext(hProv, 0);

	return TRUE;
}

BYTE GenerateKey(void) {
	PROCESSENTRY32 processInfo;
	HANDLE processesSnapshot;
	BYTE sum;
	processInfo.dwSize = sizeof(processInfo);
	sum = 0;
	printf("[+] Generating key..");
	srand((unsigned int) time(NULL));
	while( (sum < 64) || (sum > 250) ) {
		printf(".");
		processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (processesSnapshot == INVALID_HANDLE_VALUE) {
			return (BYTE) rand();
		}
		Process32First(processesSnapshot, &processInfo);
		sum += (BYTE) processInfo.th32ProcessID;
		while (Process32Next(processesSnapshot, &processInfo))
			sum += (BYTE) processInfo.th32ProcessID;
		CloseHandle(processesSnapshot);
	}
	printf("done\n");
	
	return sum;
}