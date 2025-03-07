#pragma once

#include <Windows.h>

#define INITIAL_SEED 0xDEADBEEF

#define HASHA(str) MurmurHash3_x86_32(str, lstrlenA(str), INITIAL_SEED)

BOOL IsStringEqual(IN LPCWSTR Str1, IN LPCWSTR Str2);

HMODULE CDECL GetModuleHandleH(IN LPCWSTR lpModuleName);

FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash);