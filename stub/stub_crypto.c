#include "stub_crypto.h"

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


BOOL Decrypt(LPBYTE bKey, LPBYTE bPlaintext, LPBYTE bCipherText, DWORD dwHowMuch) {
	HCRYPTPROV hProv;
	HCRYPTKEY  hKey;
	HCRYPTHASH hHash;
	LPBYTE lpExpKey;
	DWORD dwBuff = dwHowMuch;
	CopyMemory(bCipherText, bPlaintext, dwHowMuch);
	
	lpExpKey = Expand(bKey);

	if (!fGetCryptCtx(&hProv, NULL, NULL, PROV_RSA_FULL, 
								CRYPT_VERIFYCONTEXT))
		return FALSE;
	if (!fCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
		return FALSE;
	if (!fHashData(hHash, lpExpKey, strlen((char *) lpExpKey), 0))
		return FALSE;
	if (!fCryptDeriveKey(hProv, CALG_RC4, hHash, CRYPT_EXPORTABLE, &hKey))
		return FALSE;
	if (!fCryptEncrypt(hKey, 0, TRUE, 0, bCipherText, &dwBuff, dwHowMuch))
		return FALSE;

	if (hKey)  fCryptDestroyKey(hKey);
	if (hHash) fCryptDestroyHash(hHash);
	if (hProv) fCryptReleaseContext(hProv, 0);

	return TRUE;
}