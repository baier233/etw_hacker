#include "filter.h"

HIDE_RULE g_HideRules[MAX_HIDE_RULES] = { 0 };
ULONG g_HideRuleCount = 0;
KSPIN_LOCK g_HideRuleLock;

NTSTATUS FilterInitialize()
{
    KeInitializeSpinLock(&g_HideRuleLock);
    RtlZeroMemory(g_HideRules, sizeof(g_HideRules));
    g_HideRuleCount = 0;
    return STATUS_SUCCESS;
}

VOID FilterCleanup()
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_HideRuleLock, &oldIrql);
    RtlZeroMemory(g_HideRules, sizeof(g_HideRules));
    g_HideRuleCount = 0;
    KeReleaseSpinLock(&g_HideRuleLock, oldIrql);
}

NTSTATUS AddHideRule(ULONG LocalAddr, USHORT LocalPort, ULONG RemoteAddr, USHORT RemotePort)
{
    KIRQL oldIrql;
    NTSTATUS status = STATUS_SUCCESS;
    
    KeAcquireSpinLock(&g_HideRuleLock, &oldIrql);
    
    if (g_HideRuleCount >= MAX_HIDE_RULES)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
    }
    else
    {
        for (ULONG i = 0; i < MAX_HIDE_RULES; i++)
        {
            if (!g_HideRules[i].Enabled)
            {
                g_HideRules[i].LocalAddr = LocalAddr;
                g_HideRules[i].LocalPort = LocalPort;
                g_HideRules[i].RemoteAddr = RemoteAddr;
                g_HideRules[i].RemotePort = RemotePort;
                g_HideRules[i].Enabled = TRUE;
                g_HideRuleCount++;
                break;
            }
        }
    }
    
    KeReleaseSpinLock(&g_HideRuleLock, oldIrql);
    return status;
}

NTSTATUS RemoveHideRule(ULONG Index)
{
    KIRQL oldIrql;
    NTSTATUS status = STATUS_SUCCESS;
    
    if (Index >= MAX_HIDE_RULES)
        return STATUS_INVALID_PARAMETER;
    
    KeAcquireSpinLock(&g_HideRuleLock, &oldIrql);
    
    if (g_HideRules[Index].Enabled)
    {
        RtlZeroMemory(&g_HideRules[Index], sizeof(HIDE_RULE));
        g_HideRuleCount--;
    }
    else
    {
        status = STATUS_NOT_FOUND;
    }
    
    KeReleaseSpinLock(&g_HideRuleLock, oldIrql);
    return status;
}

VOID ClearAllHideRules()
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_HideRuleLock, &oldIrql);
    RtlZeroMemory(g_HideRules, sizeof(g_HideRules));
    g_HideRuleCount = 0;
    KeReleaseSpinLock(&g_HideRuleLock, oldIrql);
}

BOOLEAN ShouldHideConnection(ULONG LocalAddr, USHORT LocalPort, ULONG RemoteAddr, USHORT RemotePort)
{
    KIRQL oldIrql;
    BOOLEAN shouldHide = FALSE;
    
    if (g_HideRuleCount == 0)
        return FALSE;
    
    KeAcquireSpinLock(&g_HideRuleLock, &oldIrql);
    
    for (ULONG i = 0; i < MAX_HIDE_RULES; i++)
    {
        if (!g_HideRules[i].Enabled)
            continue;
        
        PHIDE_RULE rule = &g_HideRules[i];
        
        if (rule->LocalAddr != 0 && rule->LocalAddr != LocalAddr)
            continue;
        if (rule->LocalPort != 0 && rule->LocalPort != LocalPort)
            continue;
        if (rule->RemoteAddr != 0 && rule->RemoteAddr != RemoteAddr)
            continue;
        if (rule->RemotePort != 0 && rule->RemotePort != RemotePort)
            continue;
        
        shouldHide = TRUE;
        break;
    }
    
    KeReleaseSpinLock(&g_HideRuleLock, oldIrql);
    return shouldHide;
}
