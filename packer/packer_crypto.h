#ifndef __PACKER_CRYPTO__
#define __PACKER_CRYPTO__

#include <windows.h>
#include <time.h>

BOOL Encrypt(LPBYTE bKey, LPBYTE bPlaintext, LPBYTE bCipherText, DWORD dwHowMuch);
BYTE GenerateKey(void);
LPBYTE Expand(LPBYTE bKey);

#endif
