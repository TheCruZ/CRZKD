#pragma once
#include "sysntifs.h"
#include "memory.h"
#include "util.h"
#include <intrin.h>
#include "io_structures.h"

extern "C" NTSTATUS Entry(PDRIVER_OBJECT, PUNICODE_STRING);

bool Cleaner();
void DEntry(PVOID);
void PathSystemObBlock();
NTSTATUS IOCTL(PDEVICE_OBJECT, PIRP Irp);
NTSTATUS NewEntry(PDRIVER_OBJECT pdriver, PUNICODE_STRING);
NTSTATUS hiddenIOCTL(PDEVICE_OBJECT, PIRP Irp);
NTSTATUS CreateClose(PDEVICE_OBJECT, PIRP irp);
OB_PREOP_CALLBACK_STATUS PreCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation);
OB_PREOP_CALLBACK_STATUS hiddenPreCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation);
