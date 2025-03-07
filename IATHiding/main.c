#include <stdio.h>
#include <Windows.h>

#include "myntdll.h"
#include "Common.h"

#define __cdecl CDECL

typedef HMODULE(WINAPI* pLoadLibraryW)(LPCWSTR lpLibFileName);

INT CDECL main(VOID) {
	
    HMODULE hKernel32 = GetModuleHandleH(L"kernel32.dll");
    if (!hKernel32) {
        printf("[-] Failed to locate kernel32.dll\n");
        return 1;
    }
    printf("[+] Kernel32.dll found at: 0x%p\n", hKernel32);

    pLoadLibraryW fnLoadLibraryW = (pLoadLibraryW)GetProcAddressH(hKernel32, HASHA("LoadLibraryW"));
    if (!fnLoadLibraryW) {
        printf("[-] Failed to resolve LoadLibraryW\n");
        return 1;
    }
    printf("[+] LoadLibraryW found at: 0x%p\n", fnLoadLibraryW);

    HMODULE hUser32 = fnLoadLibraryW(L"user32.dll");
    if (!hUser32) {
        printf("[-] Failed to load user32.dll\n");
        return 1;
    }
    printf("[+] Successfully loaded user32.dll at: 0x%p\n", hUser32);

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return ERROR_SUCCESS;
}