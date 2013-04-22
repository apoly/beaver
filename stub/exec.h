#ifndef __EXEC__
#define __EXEC__

#include <Windows.h>
#include <stdlib.h>
#include "utils.h"
#include "stub_PE.h"

int limits[5];
BOOL done[5];
DWORD res;
BOOL ret;

void init(void);
void Execute(int n, LPBYTE lpPayload);
int Ackermann(int start, int finish, LPBYTE lpPayload);

#endif