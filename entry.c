#include "etw.h"

extern PVOID cpu_clock;
extern PVOID cpu_lock_orig;

VOID DriverUnload(PDRIVER_OBJECT driver)
{
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[%s] ckcl cpulock has been repaired.\n", __FUNCTION__);
	InterlockedExchange64(cpu_clock, cpu_lock_orig);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[%s] driver unload ...\n", __FUNCTION__);
}

// 详见 https://bbs.kanxue.com/thread-289632.htm
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING reg_path)
{
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[%s] driver load ...\n", __FUNCTION__);
	driver->DriverUnload = DriverUnload;

	// Initialize 函数中缺少守护线程检查 ckcl 结构体中的 cpulock 函数指针
	Initialize(circular_kernel_context_logger);

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[%s] Driver return...\n", __FUNCTION__);
	return STATUS_SUCCESS;
}

