#ifndef __STUB_CRYPTO__
#define __STUB_CRYPTO__

#include <windows.h>
#include <wincrypt.h>
#include "utils.h"

BOOL Decrypt(LPBYTE bKey, LPBYTE bPlaintext, LPBYTE bCipherText, DWORD dwHowMuch);
LPBYTE Expand(LPBYTE bKey);

#endif