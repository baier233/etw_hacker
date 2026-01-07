#include "sstd.h"

PULONG64 ssdt_service_table;

BOOLEAN InitSsdtService()
{
	PUCHAR p = (PUCHAR)__readmsr(0xC0000082) - 0x1805ec;
	if (*(PUSHORT)p == 0x8d4c && *(PUSHORT)(p + 7) == 0x8d4c)
	{
		ssdt_service_table = *(PULONG *)(*(PLONG32)(p + 3) + p + 7);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[%s] SSDT: 0x%p\n", __FUNCTION__, ssdt_service_table);
		return  TRUE;
	} 
	else
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[%s] Read SSDT table failed.\n", __FUNCTION__);
		return FALSE;
	}
}

PVOID GetSystemServiceRoutineAddress(ULONG systam_call_number)
{
repeat:
	if (ssdt_service_table)
	{
		PULONG32 func_dentry = (PULONG32)(systam_call_number * 4 + (ULONG64)ssdt_service_table);
		PVOID func = (PVOID)((*func_dentry >> 4) + (ULONG64)ssdt_service_table);
		// DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[%s] Systam service %d -> 0x%p\n.", __FUNCTION__, systam_call_number, func);
		return func;
	}
	else
	{
		if (InitSsdtService())
			goto repeat;
		else
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[%s] SSDT service error.\n", __FUNCTION__);
			return NULL;
		}
	}
}

BOOLEAN IsKernelStackExpend(ULONG systam_call_number)
{
	ULONG32 func_dentry = *(PULONG32)(systam_call_number * 4 + (ULONG64)ssdt_service_table);
	return func_dentry & 0xf;
}