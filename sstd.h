#pragma once
#include <ntddk.h>

BOOLEAN InitSsdtService();
PVOID GetSystemServiceRoutineAddress(ULONG systam_call_number);
BOOLEAN IsKernelStackExpend(ULONG systam_call_number);