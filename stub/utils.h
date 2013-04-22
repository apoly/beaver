#ifndef __UTILS_
#define __UTILS_

#include <Windows.h>
#include <stdio.h>
#include "letters.h"

typedef BOOL	(__stdcall *pCreateProc)(LPCTSTR, LPTSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCTSTR, LPSTARTUPINFO, LPPROCESS_INFORMATION);
typedef LONG	(__stdcall *pNTUnmapViewOfSections)(HANDLE, PVOID);
typedef LPVOID	(__stdcall *pVAlloc)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL	(__stdcall *pWriteProcMem)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef BOOL	(__stdcall *pGetThreadCon)(HANDLE, LPCONTEXT);
typedef BOOL	(__stdcall *pSetThreadCon)(HANDLE, const CONTEXT*);
typedef DWORD	(__stdcall *pResumeThread)(HANDLE);
typedef DWORD	(__stdcall *pGetModFileName) (HMODULE, LPTSTR, DWORD);
typedef BOOL	(__stdcall *pCryptGetCtx) (HCRYPTPROV *, LPCTSTR, LPCTSTR, DWORD, DWORD);
typedef BOOL	(__stdcall *pCryptCreateHash) (HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, HCRYPTHASH *);
typedef BOOL	(__stdcall *pCryptHashData) (HCRYPTHASH, BYTE *, DWORD, DWORD);
typedef BOOL	(__stdcall *pCryptDeriveKey) (HCRYPTPROV, ALG_ID, HCRYPTHASH, DWORD, HCRYPTKEY *);
typedef BOOL	(__stdcall *pCryptEncrypt) (HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE *, DWORD *, DWORD);
typedef BOOL	(__stdcall *pCryptGenRandom) (HCRYPTPROV, DWORD, BYTE *);
typedef BOOL	(__stdcall *pCryptDestroyKey) (HCRYPTKEY);
typedef BOOL	(__stdcall *pCryptDestroyHash) (HCRYPTHASH);
typedef BOOL	(__stdcall *pCryptReleaseContext) (HCRYPTPROV, DWORD);

extern pCreateProc fCreateProc;
extern pNTUnmapViewOfSections fNTUnmap;
extern pSetThreadCon fSetThrCtx;	
extern pVAlloc fVAlloc;
extern pWriteProcMem fWriteProcMem;
extern pGetThreadCon fGetThrCtx;
extern pResumeThread fResumeThr;
extern pGetModFileName fGetModFname;
extern pCryptGetCtx fGetCryptCtx;
extern pCryptCreateHash fCreateHash;
extern pCryptHashData fHashData;
extern pCryptDeriveKey fCryptDeriveKey;
extern pCryptEncrypt fCryptEncrypt;
extern pCryptGenRandom fCryptGenRandom;
extern pCryptDestroyKey fCryptDestroyKey;
extern pCryptDestroyHash fCryptDestroyHash;
extern pCryptReleaseContext fCryptReleaseContext;

BOOL FillApi(void);

void DebugPrintA(char *format, ...);

#endif