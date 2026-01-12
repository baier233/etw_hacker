#pragma once
#include <ntddk.h>

typedef struct _DYNAMIC_OFFSETS {
    ULONG KThread_SystemCallNumber;
    ULONG KThread_TrapFrame;
    ULONG KThread_Process;
    ULONG SiloGlobals_EtwSiloState;
    ULONG EtwSiloState_LoggerContext;
    ULONG LoggerContext_GetCpuClock;
    ULONG EtwRegEntry_Callback;
    BOOLEAN Initialized;
} DYNAMIC_OFFSETS, *PDYNAMIC_OFFSETS;

extern DYNAMIC_OFFSETS g_Offsets;

NTSTATUS InitializeDynamicOffsets();

#define KTHREAD_SYSCALL_NUMBER(thread)  (*(PULONG)((ULONG64)(thread) + g_Offsets.KThread_SystemCallNumber))
#define KTHREAD_TRAP_FRAME(thread)      (*(PULONG64*)((ULONG64)(thread) + g_Offsets.KThread_TrapFrame))
#define KTHREAD_PROCESS(thread)         (*(PVOID*)((ULONG64)(thread) + g_Offsets.KThread_Process))
