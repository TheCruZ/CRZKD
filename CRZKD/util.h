#pragma once
#include "sysntifs.h"
#include "memory.h"
#include <intrin.h>
#include "Global.h"

#ifdef _DEBUG_
#define Log(text,...) DbgPrintEx(0,0,text,__VA_ARGS__)
#else
#define Log(text,...)
#endif

bool ClearCacheEntry(UNICODE_STRING name);
HANDLE FindProcessByName(wchar_t* name);
BOOLEAN ModRemoveEntryList(_In_ PLIST_ENTRY Entry);
PVOID GetModuleBaseAddress(PCHAR name, PULONG out_size);
BOOLEAN bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask);
uintptr_t FindPattern(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, char* szMask);
PVOID ResolveRelativeAddress(_In_ PVOID Instruction, _In_ ULONG OffsetOffset, _In_ ULONG InstructionSize);
void WriteReadOnly(PVOID location, PBYTE buffer, ULONG size);
PVOID FindSection(uintptr_t base, char* name, PULONG size);
PUCHAR LockPage(void* ptr, ULONG size, PMDL* Mdl);
void UnLockPage(PMDL Mdl);
void XOR(BYTE* data, size_t size);
NTSTATUS ObReg();
void FixSystemObBlock();
void PathSystemObBlock();