#include "offsets.h"

DYNAMIC_OFFSETS g_Offsets = { 0 };

static ULONG FindKThreadProcessOffset()
{
    PKTHREAD thread = KeGetCurrentThread();
    PEPROCESS process = PsGetCurrentProcess();
    
    for (ULONG offset = 0x200; offset < 0x300; offset += 8)
    {
        __try
        {
            PVOID ptr = *(PVOID*)((ULONG64)thread + offset);
            if (ptr == process)
                return offset;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
    
    return 0x220;
}

static NTSTATUS FindSiloOffsets(PULONG pSiloGlobals_EtwState, PULONG pEtwState_LoggerContext)
{
    UNICODE_STRING funcName;
    RtlInitUnicodeString(&funcName, L"PsGetServerSiloServiceSessionId");
    PUCHAR func = (PUCHAR)MmGetSystemRoutineAddress(&funcName);
    
    if (!func)
        return STATUS_NOT_FOUND;
    
    *pSiloGlobals_EtwState = 0x360;
    *pEtwState_LoggerContext = 0x1b0;
    
    __try
    {
        PULONG64 PspHostSiloGlobals = (PULONG64)(*(PULONG32)(func + 3) + (LONG64)func + 7);
        
        if (!MmIsAddressValid(PspHostSiloGlobals))
            return STATUS_SUCCESS;
        
        for (ULONG offset = 0x300; offset < 0x450; offset += 8)
        {
            PVOID ptr = *(PVOID*)((ULONG64)PspHostSiloGlobals + offset);
            if (ptr && MmIsAddressValid(ptr))
            {
                for (ULONG offset2 = 0x180; offset2 < 0x220; offset2 += 8)
                {
                    PVOID loggerArray = *(PVOID*)((ULONG64)ptr + offset2);
                    if (loggerArray && MmIsAddressValid(loggerArray))
                    {
                        PVOID ckcl = ((PVOID*)loggerArray)[2];
                        if (ckcl && MmIsAddressValid(ckcl))
                        {
                            *pSiloGlobals_EtwState = offset;
                            *pEtwState_LoggerContext = offset2;
                            return STATUS_SUCCESS;
                        }
                    }
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    
    return STATUS_SUCCESS;
}

NTSTATUS InitializeDynamicOffsets()
{
    if (g_Offsets.Initialized)
        return STATUS_SUCCESS;
    
    g_Offsets.KThread_SystemCallNumber = 0x80;
    g_Offsets.KThread_TrapFrame = 0x90;
    g_Offsets.KThread_Process = FindKThreadProcessOffset();
    
    FindSiloOffsets(&g_Offsets.SiloGlobals_EtwSiloState, &g_Offsets.EtwSiloState_LoggerContext);
    
    g_Offsets.LoggerContext_GetCpuClock = 0x28;
    g_Offsets.EtwRegEntry_Callback = 0x30;
    
    g_Offsets.Initialized = TRUE;
    
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[offsets] KThread: 0x%X/0x%X/0x%X, Silo: 0x%X/0x%X\n",
        g_Offsets.KThread_SystemCallNumber,
        g_Offsets.KThread_TrapFrame,
        g_Offsets.KThread_Process,
        g_Offsets.SiloGlobals_EtwSiloState,
        g_Offsets.EtwSiloState_LoggerContext);
    
    return STATUS_SUCCESS;
}
