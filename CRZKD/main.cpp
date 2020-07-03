#include "main.h"

PDEVICE_OBJECT pDeviceObject;
UNICODE_STRING dev, dos;

uintptr_t Global::hookHolderModule = 0;
ULONG Global::hookHolderSize = 0;

uintptr_t Global::ntoskrnlModule = 0;
ULONG Global::ntoskrnlSize = 0;

uintptr_t Global::IOCTLHookPoint = 0;
uintptr_t Global::EndIOCTLHookPoint = 0;
uintptr_t Global::ObCallbackHookPoint = 0;

uintptr_t Global::HookBase = 0;

bool cleaned = false;

KMUTANT mutexOBObject = { 0 };
KMUTANT mutexIOObject = { 0 };

ULONG protected_process = 0;

uintptr_t HPrecallbackSize = 0;
uintptr_t HIOCTLSize = 0;

void WaitMutex(KMUTANT* mutex) {
	KeWaitForSingleObject(mutex, Executive, KernelMode, FALSE, NULL);
}
void ReleaseMutex(KMUTANT* mutex) {
	KeReleaseMutex(mutex, FALSE);
}

OB_PREOP_CALLBACK_STATUS PreCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation) {
	WaitMutex(&mutexIOObject);
	XOR((BYTE*)hiddenPreCallback, HPrecallbackSize);
	OB_PREOP_CALLBACK_STATUS result = hiddenPreCallback(RegistrationContext, pOperationInformation);
	XOR((BYTE*)hiddenPreCallback, HPrecallbackSize);
	ReleaseMutex(&mutexIOObject);
	return result;
}

OB_PREOP_CALLBACK_STATUS hiddenPreCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation) {
	UNREFERENCED_PARAMETER(RegistrationContext);
	PEPROCESS OpenedProcess = (PEPROCESS)pOperationInformation->Object;

	if (protected_process == 0)
		return OB_PREOP_SUCCESS;

	PEPROCESS protectedProcess = {};
	PsLookupProcessByProcessId((HANDLE)protected_process, &protectedProcess);

	if (protectedProcess == OpenedProcess)
	{
		if ((pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE || pOperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)) {
			pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
		}
	}
	return OB_PREOP_SUCCESS;
}

NTSTATUS NewEntry(PDRIVER_OBJECT pdriver, PUNICODE_STRING) {

	BYTE InjectBytes[] = { 0x90, 0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, 0xFF, 0xE0 };

	*(uintptr_t*)&InjectBytes[3] = (uintptr_t)IOCTL;
	WriteReadOnly((PVOID)Global::IOCTLHookPoint, InjectBytes, sizeof(InjectBytes));
	*(uintptr_t*)&InjectBytes[3] = (uintptr_t)CreateClose;
	WriteReadOnly((PVOID)Global::EndIOCTLHookPoint, InjectBytes, sizeof(InjectBytes));
	*(uintptr_t*)&InjectBytes[3] = (uintptr_t)PreCallback;
	WriteReadOnly((PVOID)Global::ObCallbackHookPoint, InjectBytes, sizeof(InjectBytes));

	HPrecallbackSize = (uintptr_t)Entry - (uintptr_t)hiddenPreCallback - 0x5;
	HIOCTLSize = (uintptr_t)hiddenPreCallback - (uintptr_t)hiddenIOCTL - 0x5;

	XOR((BYTE*)hiddenIOCTL, HIOCTLSize);
	XOR((BYTE*)hiddenPreCallback, HPrecallbackSize);
	XOR((BYTE*)FindProcessByName, (uintptr_t)FindSection - (uintptr_t)FindProcessByName - 0x5);

	//Mutex needed to prevent 2 IOCTL trying to encrypt/decrypt the code memory at same time causing an execution error
	Log("mutex init...\n");
	KeInitializeMutex(&mutexOBObject, 0);
	KeInitializeMutex(&mutexIOObject, 0);
	Log("mutex initialized\n");

	//Register Handle creation callback
	NTSTATUS status = ObReg();
	if (!NT_SUCCESS(status)) {
		Log("cant obreg %p %p\n", status, Global::ObCallbackHookPoint);
	}
	else {
		Log("obreg ok\n"); //Device for the IOCTL
		if (!NT_SUCCESS(IoCreateDevice(pdriver, 0, &dev, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject))) {
			Log("cant dev\n");
		}
		//Symbolic Link for the usermode app
		if (!NT_SUCCESS(IoCreateSymbolicLink(&dos, &dev))) {
			Log("cant link\n");
		}

		pdriver->MajorFunction[IRP_MJ_CREATE] = (PDRIVER_DISPATCH)Global::EndIOCTLHookPoint;
		pdriver->MajorFunction[IRP_MJ_CLOSE] = (PDRIVER_DISPATCH)Global::EndIOCTLHookPoint;
		pdriver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = (PDRIVER_DISPATCH)Global::IOCTLHookPoint;

		pDeviceObject->Flags |= DO_DIRECT_IO;
		pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
	}

	//PEPROCESS me = IoGetCurrentProcess();
	//for (int i = 0x200; i < 0x600; i++) {
	//	char sysname[] = { 'S','y','s','t','e','m','\0' };
	//	if (strcmp(((char*)me) + i, sysname) == 0) {
	//		PEPROCESS_NAME_OFFSET = i;
	//		break;
	//	}
	//}

	Log("Partial Ready\n");
	return STATUS_SUCCESS;
}

bool Cleaner() {
	BYTE buffer[26] = { 'i', 0x00, 'q', 0x00, 'v', 0x00, 'w', 0x00, '6', 0x00, '4', 0x00, 'e', 0x00, '.', 0x00, 's', 0x00, 'y', 0x00, 's', 0x00, 0x00, 0x00, 0x00, 0x00 };
	UNICODE_STRING intelDrv;
	RtlInitUnicodeString(&intelDrv, (PCWSTR)buffer);// L"iqvw64e.sys");  << if you modify your kdmapper driver name modify this buffer too!!!!!!!!
	Log("Going to clear the shit");
	if (!ClearCacheEntry(intelDrv)) {
		Log("Can't clear Piddbcache");
		return false;
	}
	Log("Clear done, cleaning traces");
	memset(intelDrv.Buffer, 0x00, 26);
	intelDrv.Length = 0;
	intelDrv.MaximumLength = 0;
	memset(buffer, 0x00, 26);

	//CHECK IN IDA YOUR FUNCTION ORDER AS MAY CHANGE IF YOU CHANGE ANYTHING IN THE CODE
	memset(DEntry, 0xCC, (uintptr_t)IOCTL - (uintptr_t)DEntry);
	memset(NewEntry, 0xCC, (uintptr_t)PreCallback - (uintptr_t)NewEntry);
	memset(Entry, 0xCC, (uintptr_t)IoGetCurrentIrpStackLocation - (uintptr_t)Entry);
	memset(KeGetCurrentIrql, 0xCC, (uintptr_t)FindProcessByName - (uintptr_t)KeGetCurrentIrql);
	memset(FindSection, 0xCC, (uintptr_t)XOR - (uintptr_t)FindSection);
	memset(bDataCompare, 0xCC, (uintptr_t)ZwQuerySystemInformation - (uintptr_t)bDataCompare);

	cleaned = true;
	return true;
}

NTSTATUS IOCTL(PDEVICE_OBJECT po, PIRP Irp) {
	WaitMutex(&mutexIOObject);
	XOR((BYTE*)hiddenIOCTL, HIOCTLSize);
	NTSTATUS result = hiddenIOCTL(po, Irp);
	XOR((BYTE*)hiddenIOCTL, HIOCTLSize);
	ReleaseMutex(&mutexIOObject);
	return result;
}

NTSTATUS hiddenIOCTL(PDEVICE_OBJECT, PIRP Irp) {
	//First time we remove the memory that will not be used anymore
	if (!cleaned) {
		if (!Cleaner()) {
			memset(Cleaner, 0xCC, (uintptr_t)CreateClose - (uintptr_t)Cleaner);
			goto out;
		}
		memset(Cleaner, 0xCC, (uintptr_t)CreateClose - (uintptr_t)Cleaner);
	}

	const IO_STACK_LOCATION stack = *IoGetCurrentIrpStackLocation(Irp);
	const ULONG ControlCode = stack.Parameters.DeviceIoControl.IoControlCode;
	if (ControlCode == REQUEST_READ_WRITE) {
		ReadWrite* cmd = (ReadWrite*)Irp->AssociatedIrp.SystemBuffer;

		Log("data pid: %d\n", cmd->DstPid);

		size_t r = 0;
		PEPROCESS SrcProc = nullptr;
		PEPROCESS DstProc = nullptr;
		if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)cmd->SrcPid, &SrcProc)) || SrcProc == nullptr) {
			goto out;
		}

		if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)cmd->DstPid, &DstProc)) || DstProc == nullptr) {
			goto out;
		}

		MmCopyVirtualMemory(SrcProc, (void*)cmd->SrcAddr, DstProc, (void*)cmd->DstAddr, cmd->size, UserMode, &r);
	}
	else if (ControlCode == GET_PID_AND_BASE) {
		PidBase* cmd = (PidBase*)Irp->AssociatedIrp.SystemBuffer;
		//Last caller of this IOCTL receive the handle creation protection
		protected_process = IoGetRequestorProcessId(Irp);

		PidBaseResponse res = { 0, 0 };
		XOR((BYTE*)FindProcessByName, (uintptr_t)FindSection - (uintptr_t)FindProcessByName - 0x5);
		res.pid = (unsigned long long)FindProcessByName(cmd->name);
		XOR((BYTE*)FindProcessByName, (uintptr_t)FindSection - (uintptr_t)FindProcessByName - 0x5);
		
		if (res.pid <= 0) {
			goto out;
		}

		PEPROCESS process = nullptr;
		NTSTATUS status = PsLookupProcessByProcessId((HANDLE)res.pid, &process);
		if (!NT_SUCCESS(status) || process == nullptr)
			goto out;

		res.baseAddr = (UINT64)PsGetProcessSectionBaseAddress(process);

		Log("Base Address: %pºn", res.baseAddr);

		PEPROCESS DstInfoProc = nullptr;
		if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)IoGetRequestorProcessId(Irp), &DstInfoProc)) || DstInfoProc == nullptr) {
			goto out;
		}

		size_t r = 0;
		MmCopyVirtualMemory(IoGetCurrentProcess(), (void*)&res, DstInfoProc, (void*)cmd->RetInfoPid, sizeof(PidBaseResponse), KernelMode, &r);
	}
out:
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS CreateClose(PDEVICE_OBJECT, PIRP irp)
{
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

void DEntry(PVOID) {
	Log("Loading...\n");

	//IOCTL Device paths YOU MUST CHANGE THIS!
	BYTE devi[] = { '\\', '\0', 'D', '\0', 'e', '\0', 'v', '\0', 'i', '\0', 'c', '\0', 'e', '\0', '\\', '\0', 'N', '\0', 's', '\0', 'i', '\0', 'L', '\0', 'o', '\0', 'o', '\0', 'k', '\0', 'u', '\0', 'p', '\0', '\0', '\0', '\0', '\0' };
	BYTE dospath[] = { '\\', '\0', 'D', '\0', 'o', '\0', 's', '\0', 'D', '\0', 'e', '\0', 'v', '\0', 'i', '\0', 'c', '\0', 'e', '\0', 's', '\0', '\\', '\0', 'N', '\0', 's', '\0', 'i', '\0', 'L', '\0', 'o', '\0', 'o', '\0', 'k', '\0', 'u', '\0', 'p','\0','\0','\0','\0', '\0' } ;
	RtlInitUnicodeString(&dev, (wchar_t*)devi);
	RtlInitUnicodeString(&dos, (wchar_t*)dospath);

	BYTE tcpipName[] = { 't', 'c', 'p', 'i', 'p', '.', 's', 'y', 's','\0' };  //Hook destination driver, YOU MUST CHANGE THIS!
	BYTE ntoskrnlName[] = { 'n', 't', 'o', 's', 'k', 'r', 'n', 'l', '.', 'e', 'x', 'e','\0' };
	Global::hookHolderModule = (uintptr_t)GetModuleBaseAddress((char*)tcpipName, &Global::hookHolderSize);
	Global::ntoskrnlModule = (uintptr_t)GetModuleBaseAddress((char*)ntoskrnlName, &Global::ntoskrnlSize);

	if (Global::hookHolderModule <= 0 || Global::hookHolderSize <= 0 ||
		Global::ntoskrnlModule <= 0 || Global::ntoskrnlSize <= 0) {
		Log("Some 0 preparation %p %p %p %p\n", Global::hookHolderModule, Global::hookHolderSize, Global::ntoskrnlModule, Global::ntoskrnlSize);
		return;
	}

	BYTE PageName[] = { 'P', 'A', 'G', 'E', 'I', 'P', 'S', 'E','\0' }; //SECTION AFTER THE SECTION WHERE I WILL PUT THE HOOK, YOU MUST CHANGE THIS!
	uintptr_t base = (uintptr_t)FindSection(Global::hookHolderModule, (char*)PageName, 0);
	if (!base) {
		Log("! failed to get \"PAGEIPSE\" !\n");
		return;
	}
	Log("PAGEIPSE ptr: %p\n", base);

	Global::HookBase = base - 0x30; //Aprox space needed for the hooks (3 hooks in this case (13*3 = 39 (0x27)))
	Log("Hooking ptr: %p\n", Global::HookBase);

	if (((PBYTE)Global::HookBase)[0] != 0x00) {
		Log("Already installed!\n");
		return;
	}

	BYTE InjectBytes[] = { 0x90, 0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, 0xFF, 0xE0 };


	//Where we will place the hooks
	Global::IOCTLHookPoint = Global::HookBase;
	Global::EndIOCTLHookPoint = Global::HookBase + sizeof(InjectBytes);
	Global::ObCallbackHookPoint = Global::HookBase + (sizeof(InjectBytes)*2);

	*(uintptr_t*)&InjectBytes[3] = (uintptr_t)NewEntry;
	WriteReadOnly((PVOID)Global::IOCTLHookPoint, InjectBytes, sizeof(InjectBytes));

	if (!NT_SUCCESS(IoCreateDriver(NULL, (PDRIVER_INITIALIZE)Global::IOCTLHookPoint))) {
		Log("Error al crear el driver...\n");
	}
}

extern "C" NTSTATUS Entry(PDRIVER_OBJECT, PUNICODE_STRING) {
	Log("Enter\n");
	HANDLE out;
	NTSTATUS result = PsCreateSystemThread(&out, GENERIC_ALL, NULL, NULL, NULL, DEntry, NULL);
	if (NT_SUCCESS(result)) {
		Log("COK\n");
		ZwClose(out);
	}
	else {
		Log("no puto thread?!");
	}
	return result;
}