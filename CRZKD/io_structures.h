#pragma once

#include "sysntifs.h"

#define REQUEST_READ_WRITE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x826, METHOD_OUT_DIRECT, FILE_ANY_ACCESS) //YOU MUST CHANGE IOCTL CODE
#define GET_PID_AND_BASE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x827, METHOD_OUT_DIRECT, FILE_ANY_ACCESS) //YOU MUST CHANGE IOCTL CODE

typedef struct _ReadWrite
{
	int SrcPid;
	uintptr_t SrcAddr;

	int DstPid;
	uintptr_t DstAddr;

	uintptr_t size;
} ReadWrite;
typedef struct _PidBase
{
	wchar_t name[200];
	uintptr_t RetInfoPid;
	uintptr_t RetInfoAddr;
} PidBase;
struct PidBaseResponse {
	unsigned long long pid;
	unsigned long long baseAddr;
};