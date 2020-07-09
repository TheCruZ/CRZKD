#include "util.h"

uintptr_t patchpoint = 0;
PVOID hRegistration = NULL;

void PathSystemObBlock() {
	BYTE pattern[] = { 0x84, 0x00, 0x00, 0x00, 0x00, 0x49, 0x8B, 0x4E, 0x00, 0x48, 0x85, 0xC9, 0x0F, 0x85 };
	BYTE mask[] = { 'c', '?', '?', '?', '?', 'c', 'c', 'c', '?', 'c', 'c', 'c', 'c', 'c',0 };
	Log("patch start point search %p\n", Global::ntoskrnlModule);
	if (patchpoint == 0)
		patchpoint = FindPattern(Global::ntoskrnlModule, Global::ntoskrnlSize, pattern, (char*)mask);

	if (patchpoint <= 0) {
		Log("OB Patch location not found!!!!!\n");
		return;
	}

	_disable();
	auto cr0 = __readcr0();
	const auto old_cr0 = cr0;
	cr0 &= ~(1UL << 16);
	__writecr0(cr0);

	memset((void*)patchpoint, 0x85, 1);

	__writecr0(old_cr0);
	_enable();

	if (((PBYTE)patchpoint)[0] != 0x85) {
		Log("Failed patch OB REGISTER %p\n", patchpoint);
		patchpoint = 0;
		return;
	}
	else {
		Log("patch point %p\n", patchpoint);
	}
	
}

void FixSystemObBlock() {
	if (patchpoint <= 0) {
		Log("OB NOT Patched !!!!!\n");
		return;
	}
	_disable();
	auto cr0 = __readcr0();
	const auto old_cr0 = cr0;
	cr0 &= ~(1UL << 16);
	__writecr0(cr0);

	memset((void*)patchpoint, 0x84, 1);

	__writecr0(old_cr0);
	_enable();
}

BOOLEAN bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask) {
	for (; *szMask; ++szMask, ++pData, ++bMask)
		if (*szMask == 'c' && *pData != *bMask)
			return 0;
	return (*szMask) == 0;
}

uintptr_t FindPattern(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, char* szMask) {
	size_t max_len = dwLen - strlen(szMask);
	for (uintptr_t i = 0; i < max_len; i++)
		if (bDataCompare((BYTE*)(dwAddress + i), bMask, szMask))
			return (uintptr_t)(dwAddress + i);
	return 0;
}

PVOID ResolveRelativeAddress(_In_ PVOID Instruction, _In_ ULONG OffsetOffset, _In_ ULONG InstructionSize)
{
	ULONG_PTR Instr = (ULONG_PTR)Instruction;
	LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
	PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);
	return ResolvedAddr;
}

NTSTATUS ObReg() {
	OB_CALLBACK_REGISTRATION obRegistration = { 0, };
	OB_OPERATION_REGISTRATION opRegistration = { 0, };
	NTSTATUS result = -1;

	obRegistration.Version = ObGetFilterVersion();
	obRegistration.OperationRegistrationCount = 1;
	RtlInitUnicodeString(&obRegistration.Altitude, L"22756"); //You should change this number should be unique read more about this -> https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/load-order-groups-and-altitudes-for-minifilter-drivers
	obRegistration.RegistrationContext = NULL;

	opRegistration.ObjectType = PsProcessType;
	opRegistration.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	opRegistration.PreOperation = (POB_PRE_OPERATION_CALLBACK)Global::ObCallbackHookPoint;
	opRegistration.PostOperation = NULL;

	obRegistration.OperationRegistration = &opRegistration;


	result = ObRegisterCallbacks(&obRegistration, &hRegistration);
	if (result == 0x0C0000022) { //if the system don't like the location for the callback when patch it and try again
		PathSystemObBlock();
		if (patchpoint > 0)
			result = ObRegisterCallbacks(&obRegistration, &hRegistration);
		FixSystemObBlock();
	}

	
	return result;
}

void XOR(BYTE* data, size_t size) {
	for (size_t i = 0; i < size; i++) {
		data[i] = data[i] ^ 0x37; //Modify this byte to any random one
	}
}

PUCHAR LockPage(void* ptr, ULONG size, PMDL* Mdl) {
	*Mdl = IoAllocateMdl(ptr, size, FALSE, FALSE, NULL);
	if (*Mdl == NULL) {
		Log("ALockPage: Error: IoAllocateMdl failed. \n");
		return NULL;
	}

	MmProbeAndLockPages(*Mdl, KernelMode, IoModifyAccess); // Can throught exceptions!!!!!!!!!!!!!!!!!!!!!!!(BSOD TO UNDERSTAND ME)

	PUCHAR Buffer = (PUCHAR)MmGetSystemAddressForMdlSafe(*Mdl, HighPagePriority);
	if (Buffer == NULL) {
		Log("ALockPage: Error: MmGetSystemAddressForMdlSafe failed. \n");
		return NULL;
	}

	if (MmProtectMdlSystemAddress(*Mdl, PAGE_EXECUTE_READWRITE) != STATUS_SUCCESS) {
		Log("ALockPage: Error: MmProtectMdlSystemAddress failed. \n");
		return NULL;
	}
	return Buffer;
}

void UnLockPage(PMDL Mdl) {
	MmUnlockPages(Mdl); // Can throught exceptions!!!!!!!!!!!!!!!!!!!!!!!(BSOD TO UNDERSTAND ME)
	IoFreeMdl(Mdl);
}

void WriteReadOnly(PVOID location, PBYTE buffer, ULONG size) {
	PMDL Mdl = NULL;
	PUCHAR WritableBuffer = LockPage(location, size, &Mdl);
	if (WritableBuffer == NULL)
		return;

	KIRQL save = KeGetCurrentIrql();
	KeRaiseIrqlToDpcLevel();

	_disable();
	auto cr0 = __readcr0();
	const auto old_cr0 = cr0;
	cr0 &= ~(1UL << 16);
	__writecr0(cr0);

	memcpy((void*)WritableBuffer, buffer, size);

	__writecr0(old_cr0);
	_enable();

	KeLowerIrql(save);
	UnLockPage(Mdl);
}

PVOID FindSection(uintptr_t base, char* name, PULONG size) {
	PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
	PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
	for (DWORD i = 0; i < headers->FileHeader.NumberOfSections; ++i) {
		PIMAGE_SECTION_HEADER section = &sections[i];
		if (memcmp(section->Name, name, 8) == 0) {
			if (size) {
				*size = section->Misc.VirtualSize;
			}
			return (PVOID)(base + section->VirtualAddress);
		}
	}
	return 0;
}

BOOLEAN ModRemoveEntryList( _In_ PLIST_ENTRY Entry ) {
	PLIST_ENTRY PrevEntry = nullptr;
	PLIST_ENTRY NextEntry = nullptr;

	NextEntry = Entry->Flink;
	PrevEntry = Entry->Blink;

	PrevEntry->Flink = NextEntry;
	NextEntry->Blink = PrevEntry;
	return (BOOLEAN)(PrevEntry->Flink == NextEntry);
}

bool ClearCacheEntry(UNICODE_STRING name) {

	if (Global::ntoskrnlModule == 0 || Global::ntoskrnlSize == 0) {
		Log("Warning no ntoskrnl found\n");
		return false;
	}

	BYTE pidlockPattern[] = { 0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0x8C };
	BYTE maskBuff1[] = { 'c', 'c', 'c', '?', '?', '?', '?', 'c', '?', '?', '?', '?', 'c', 'c', 'c', 0x00 };
	uintptr_t PiDDBLockPtr = FindPattern(Global::ntoskrnlModule, Global::ntoskrnlSize, pidlockPattern, (char*)maskBuff1);

	if (PiDDBLockPtr == NULL) {
		Log("Warning no PiDDBLockPtr found\n");
		return false;
	}

	Log("PiDDBLockPtr %llx\n", PiDDBLockPtr);

	BYTE pidtablePattern[] = { 0x66, 0x03, 0xD2, 0x48, 0x8D, 0x0D };
	BYTE maskBuff2[] = { 'c', 'c', 'c', 'c', 'c', 'c', 0x00 };
	uintptr_t PiDDBCacheTablePtr = FindPattern(Global::ntoskrnlModule, Global::ntoskrnlSize, pidtablePattern,(char*)maskBuff2);
	if (PiDDBCacheTablePtr == NULL) {
		Log("Warning no PiDDBCacheTablePtr found\n");
		return false;
	}

	Log("PiDDBCacheTablePtr %llx\n", PiDDBCacheTablePtr);
	
	PERESOURCE PiDDBLock = (PERESOURCE)ResolveRelativeAddress((PVOID)PiDDBLockPtr, 3, 7);
	PRTL_AVL_TABLE PiDDBCacheTable = (PRTL_AVL_TABLE)ResolveRelativeAddress((PVOID)PiDDBCacheTablePtr, 6, 10);

	PiDDBCacheTable->TableContext = (PVOID)1;

	// build a lookup entry
	PiDDBCacheEntry lookupEntry = { 0 };
	lookupEntry.DriverName = name;
	Log("to clear %wZ\n", lookupEntry.DriverName);
	
	// acquire the ddb resource lock
	if (!ExAcquireResourceExclusiveLite(PiDDBLock, TRUE)) {
		Log("Can't acquire resource\n");
		return false;
	}
	
	// search our entry in the table
	PiDDBCacheEntry* pFoundEntry = (PiDDBCacheEntry*)RtlLookupElementGenericTableAvl(PiDDBCacheTable, &lookupEntry);
	if (pFoundEntry == nullptr) {
		Log("Not found in cache\n");
		ExReleaseResourceLite(PiDDBLock);
		return false;
	}
	Log("Found bad driver %wZ\n", pFoundEntry->DriverName);
	// first, unlink from the list
	if (!ModRemoveEntryList(&pFoundEntry->List)) {
		Log("Can't unlink from list\n");
		ExReleaseResourceLite(PiDDBLock);
		return false;
	}
	Log("RM gtable\n");
	// then delete the element from the avl table
	if (!RtlDeleteElementGenericTableAvl(PiDDBCacheTable, pFoundEntry)) {
		Log("Can't delete from cache\n");
		ExReleaseResourceLite(PiDDBLock);
		return false;
	}
	Log("Release resource\n");
	// release the ddb resource lock
	ExReleaseResourceLite(PiDDBLock);
	Log("Cleaned %wZ\n", name);

	ClearCacheEntry(name); // if found clear again to remove every repeat
	return true;
}

HANDLE FindProcessByName(wchar_t* name) {
	back:
	ULONG bytes = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemProcessInformation, 0, bytes, &bytes);
	if (!bytes) {
		return (HANDLE)0;
	}
	PVOID data = ExAllocatePool(NonPagedPool, bytes); //abrimos espacio para la lista de procesos
	if (data == 0) {
		return (HANDLE)0;
	}
	status = ZwQuerySystemInformation(SystemProcessInformation, data, bytes, &bytes);
	if (!NT_SUCCESS(status)) {
		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			ExFreePool(data);
			goto back;
		}
		else {
			ExFreePool(data);
			return (HANDLE)status;
		}
	}
	PSYSTEM_PROCESS_INFORMATION pProcess = (PSYSTEM_PROCESS_INFORMATION)data;
	if (pProcess == 0) {
		ExFreePool(data);
		return (HANDLE)0;
	}
	Log("Searching for %ws\n", name);
	while (TRUE) {
		Log("Reading %wZ\n", pProcess->ImageName);
		if (&pProcess->ImageName != nullptr && pProcess->ImageName.Length == wcslen(name) * sizeof(wchar_t)) {
			if (memcmp(pProcess->ImageName.Buffer, name, wcslen(name) * sizeof(wchar_t)) == 0) {
				Log("Process name: %wZ  - Process ID: %d\n", pProcess->ImageName, pProcess->UniqueProcessId);
				HANDLE id = pProcess->UniqueProcessId;
				ExFreePool(data);
				return id;
			}
			else {
				Log("Name missmatch\n");
			}
		}
		else {
			Log("Len missmatch %d vs %d\n", pProcess->ImageName.Length, wcslen(name) * sizeof(wchar_t));
		}

		if (pProcess->NextEntryOffset == 0) {
			break;
		}
		pProcess = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pProcess + pProcess->NextEntryOffset); // Calculate the address of the next entry.
	}
	ExFreePool(data);
	return (HANDLE)0;
}

PVOID GetModuleBaseAddress(PCHAR name, PULONG out_size) {
	PVOID addr = 0;
	ULONG size = 0;
	NTSTATUS status = 0;

retry:
	
	status = ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &size);
	if (STATUS_INFO_LENGTH_MISMATCH != status) {
		Log("! ZwQuerySystemInformation for size failed: %p !\n", status);
		return addr;
	}

	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPool, size);
	if (!modules) {
		Log("! failed to allocate %d bytes for modules !\n", size);
		return addr;
	}

	if (!NT_SUCCESS(status = ZwQuerySystemInformation(SystemModuleInformation, modules, size, 0))) {
		ExFreePool(modules);
		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			goto retry;
		}
		else {
			return addr;
		}
	}

	for (ULONG i = 0; i < modules->NumberOfModules; ++i) {
		RTL_PROCESS_MODULE_INFORMATION m = modules->Modules[i];
		Log("Module name: %s\n", (PCHAR)m.FullPathName);
		if (strstr((PCHAR)m.FullPathName, name)) {
			addr = m.ImageBase;
			if (out_size) {
				*out_size = m.ImageSize;
			}
			break;
		}
	}

	ExFreePool(modules);
	return addr;
}
