#include "etw.h"
#include "sstd.h"

PVOID cpu_clock;
PVOID cpu_lock_orig;
PULONG64 KiDynamicTraceMask;
const PVOID cpu_lock_wk = WkGetCpuLock;

NTSTATUS ModifyTraceSettings(TRACE_TYPE trace_type)
{
	const unsigned long tag = 'wket';

	// 申请结构体空间
	CKCL_TRACE_PROPERTIES* properties = (CKCL_TRACE_PROPERTIES*)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, tag);
	if (!properties)
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[%s] allocate ckcl trace properties struct failed. \n", __FUNCTION__);
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	// 申请保存名称的空间
	WCHAR* provider_name = (WCHAR*)ExAllocatePoolWithTag(NonPagedPool, 256 * sizeof(WCHAR), tag);
	if (!provider_name)
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[%s] allocate provider name failed. \n", __FUNCTION__);
		ExFreePoolWithTag(properties, tag);
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	// 清空内存
	RtlZeroMemory(properties, PAGE_SIZE);
	RtlZeroMemory(provider_name, 256 * sizeof(WCHAR));

	// 名称赋值
	RtlCopyMemory(provider_name, L"Circular Kernel Context Logger", sizeof(L"Circular Kernel Context Logger"));
	RtlInitUnicodeString(&properties->provider_name, (const WCHAR*)provider_name);

	// 唯一标识符
	GUID ckcl_session_guid = { 0x54dea73a, 0xed1f, 0x42a4, { 0xaf, 0x71, 0x3e, 0x63, 0xd0, 0x56, 0xf1, 0x74 } };

	// 结构体填充
	properties->event_trace_properties.Wnode.BufferSize = PAGE_SIZE;
	properties->event_trace_properties.Wnode.Flags = 0x00020000;
	properties->event_trace_properties.Wnode.Guid = ckcl_session_guid;
	properties->event_trace_properties.Wnode.ClientContext = 3;
	properties->event_trace_properties.BufferSize = sizeof(unsigned long);
	properties->event_trace_properties.MinimumBuffers = 2;
	properties->event_trace_properties.MaximumBuffers = 2;
	properties->event_trace_properties.LogFileMode = 0x00000400;
	properties->event_trace_properties.EnableFlags = 0x00000080;

	// 执行操作
	ULONG length = 0;
	NTSTATUS status = NtTraceControl(syscall_trace, properties, PAGE_SIZE, properties, PAGE_SIZE, &length);

	// 释放内存空间
	ExFreePoolWithTag(provider_name, tag);
	ExFreePoolWithTag(properties, tag);

	return status;
}

NTSTATUS Initialize(ULONG LoggerId)
{
	NTSTATUS status = ModifyTraceSettings(syscall_trace);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[%s] start ckcl failed. \n", __FUNCTION__);
		return status;
	}

	// 解析 PsGetServerSiloActiveConsoleId 函数地址
	UNICODE_STRING str;
	WCHAR func_name[] = L"PsGetServerSiloServiceSessionId";
	RtlInitUnicodeString(&str, func_name);
	PVOID func = (ULONG64)MmGetSystemRoutineAddress(&str);

	// 获取 ckcl logger context 地址
	PULONG64 PspHostSiloGlobals = (PULONG64)(*(PULONG32)((LONG64)func + 3) + (LONG64)func + 7);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[%s] PspHostSiloGlobals: 0x%p. \n", __FUNCTION__, PspHostSiloGlobals);
	PULONG64 EtwpHostSiloState = *(PULONG64)((ULONG64)PspHostSiloGlobals + 0x360);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[%s] EtwpHostSiloState: 0x%p. \n", __FUNCTION__, EtwpHostSiloState);
	PULONG64 EtwpLoggerContext = *(PULONG64)((ULONG64)EtwpHostSiloState + 0x1b0);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[%s] EtwpLoggerContext: 0x%p. \n", __FUNCTION__, EtwpLoggerContext);
	PULONG64 logger_context = (PULONG64)(EtwpLoggerContext[LoggerId]);

	// 篡改 cpu lock
	cpu_clock = (PVOID)((ULONG64)logger_context + 0x28);
	cpu_lock_orig = InterlockedExchange64(cpu_clock, cpu_lock_wk);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[%s] LoggerContext: orgi -> 0x%p, new -> 0x%p. \n", __FUNCTION__, cpu_lock_orig, cpu_lock_wk);

	// 获取 KiDynamicTraceMask, 这将影响函数执行流
	WCHAR func_name2[] = L"KeSetTracepoint";
	RtlInitUnicodeString(&str, func_name2);
	func = (PVOID)((ULONG64)MmGetSystemRoutineAddress(&str) + 0x46e);
	KiDynamicTraceMask = (PULONG64)(*(PLONG)((LONG64)func + 3) + (LONG64)func + 8);

	return STATUS_SUCCESS;
}

ULONG64 WkGetCpuLock()
{
	ULONG wk_systam_call_number = 0x3f;

	// 过滤内核模式的调用
	if (ExGetPreviousMode() == KernelMode)
		goto tag_rdtsc;

	// 读取系统调用号和Trap_Frame
	PKTHREAD current_thread = (PKTHREAD)__readgsqword(0x188);
	ULONG systam_call_number = *(PULONG)((ULONG64)current_thread + 0x80);
	if (systam_call_number != wk_systam_call_number) 
		goto tag_rdtsc;
	PULONG64 trap_frame = *(PULONG64*)((ULONG64)current_thread + 0x90);

	// 获取系统调用服务例程函数地址, 判断栈帧是否存在扩展的情况
	PVOID func = GetSystemServiceRoutineAddress(wk_systam_call_number);
	ULONG64 expend_size = IsKernelStackExpend(wk_systam_call_number) * 0x70;

	/* 
	 *	篡改栈帧中的系统调用服务例程地址 
	 *	这适用于调用系统服务例程前的时机, 即 PerfInfoLogSysCallEntry, 可选择直接劫持或篡改参数
	 *	当触发 PerfInfoLogSysCallExit 时, 系统调用已经执行, 可篡改返回值
	 */

	// 此时默认开启 syscall trace, 满足: PerfGlobalGroupMask+8 & 0x40 == TRUE
	// path 1: PerfInfoLogSysCallEntry
	ULONG64 stack_sub = 0x50 + 0x8 + 0x30 + expend_size;	// 定位 magic
	if (*(KiDynamicTraceMask) & 1)
	{
		// 以开启动态调试
		// path 2: KiTrackSystemCallEntry->PerfInfoLogSysCallEntry
		stack_sub += 0x58;
	}
		
	PULONG magic_pointer1 = (PULONG)((ULONG64)trap_frame - stack_sub);
	PUSHORT magic_pointer2 = (PUSHORT)((ULONG64)trap_frame - stack_sub - 8);
	if (*magic_pointer1 == ETW_TRACE_MAGIC_SYSCALL)
	{
		PKPROCESS process = *(PKPROCESS *)((ULONG64)current_thread + 0x220);
		PUWSTR image_file_name = (PUWSTR)((ULONG64)process + 0x450);

		if (*magic_pointer2 == ETW_TRACE_MAGIC_SYSCALL_EXIT)
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[%s] PerfInfoLogSysCallExit: Caller -> %s\n", __FUNCTION__, image_file_name);
			goto tag_rdtsc;
		}

		if (*magic_pointer2 == ETW_TRACE_MAGIC_SYSCALL_ENTRY)
		{		
			PULONG64 func_addr = (PVOID)((ULONG64)trap_frame - 0x10 - expend_size);
			PVOID func_stack = (PVOID)*func_addr;
			if (func_stack != func)
			{
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[%s] Stack frame has been tampered with: orig -> 0x%p, new -> 0x%p. Caller: %s.\n", __FUNCTION__, func, func_stack, image_file_name);
				goto tag_rdtsc;
			}

			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[%s] PerfInfoLogSysCallEntry: Caller -> %s\n", __FUNCTION__, image_file_name);
		} 
		
	}
	else
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[%s] Parsing failed.\n", __FUNCTION__);
	}
	
tag_rdtsc:
	// 调用原函数
	return __rdtsc();
}