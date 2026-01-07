#pragma once
#include <ntddk.h>

typedef struct _WNODE_HEADER
{
	ULONG BufferSize;
	ULONG ProviderId;
	union {
		ULONG64 HistoricalContext;
		struct {
			ULONG Version;
			ULONG Linkage;
		};
	};
	union {
		HANDLE KernelHandle;
		LARGE_INTEGER TimeStamp;
	};
	GUID Guid;
	ULONG ClientContext;
	ULONG Flags;
} WNODE_HEADER, * PWNODE_HEADER;


typedef struct _EVENT_TRACE_PROPERTIES
{
	WNODE_HEADER Wnode;
	ULONG BufferSize;
	ULONG MinimumBuffers;
	ULONG MaximumBuffers;
	ULONG MaximumFileSize;
	ULONG LogFileMode;
	ULONG FlushTimer;
	ULONG EnableFlags;
	union {
		LONG AgeLimit;
		LONG FlushThreshold;
	} DUMMYUNIONNAME;
	ULONG NumberOfBuffers;
	ULONG FreeBuffers;
	ULONG EventsLost;
	ULONG BuffersWritten;
	ULONG LogBuffersLost;
	ULONG RealTimeBuffersLost;
	HANDLE LoggerThreadId;
	ULONG LogFileNameOffset;
	ULONG LoggerNameOffset;
} EVENT_TRACE_PROPERTIES, * PEVENT_TRACE_PROPERTIES;


typedef struct _CKCL_TRACE_PROPERIES
{
	EVENT_TRACE_PROPERTIES event_trace_properties;
	ULONG64 unknown[3];
	UNICODE_STRING provider_name;
} CKCL_TRACE_PROPERTIES, * PCKCL_TRACE_PROPERTIES; 


typedef enum _TRACE_TYPE
{
	start_trace = 1,
	stop_trace = 2,
	query_trace = 3,
	syscall_trace = 4,
	flush_trace = 5
} TRACE_TYPE;

typedef enum _LOGGER_ID
{
	nt_kernel_logger = 0,
	circular_kernel_context_logger = 2
} LOGGER_ID;


NTSTATUS NTAPI NtTraceControl(
	ULONG FunctionCode,
	PVOID InBuffer,
	ULONG InBufferLen,
	PVOID OutBuffer,
	ULONG OutBufferLen,
	PULONG ReturnLength
);

NTSTATUS Initialize(ULONG LoggerId);
ULONG64 WkGetCpuLock();
NTSTATUS ModifyTraceSettings(TRACE_TYPE trace_type);

#define ETW_TRACE_MAGIC_SYSCALL ((unsigned long)0x501802)
#define ETW_TRACE_MAGIC_SYSCALL_ENTRY ((unsigned short)0xF33)
#define ETW_TRACE_MAGIC_SYSCALL_EXIT ((unsigned short)0xF34)



