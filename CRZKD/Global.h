#pragma once
#include "sysntifs.h"

namespace Global {
	extern uintptr_t hookHolderModule;
	extern ULONG hookHolderSize;
	
	extern uintptr_t ntoskrnlModule;
	extern ULONG ntoskrnlSize;

	extern uintptr_t ObCallbackHookPoint;

	extern uintptr_t IOCTLHookPoint;
	extern uintptr_t EndIOCTLHookPoint;

	extern uintptr_t HookBase;
}