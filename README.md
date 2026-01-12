# etw-hacker

Fork 自 [Wanhu-Nie/etw_hacker](https://github.com/Wanhu-Nie/etw_hacker)，增加网络连接隐藏功能。

CKCL logger context 通过 silo 机制定位，无需特征码扫描：
> PspHostSiloGlobals::EtwSiloState -> EtwpHostSiloState::EtwpLoggerContext[LoggerId] -> ckcl

通过 TrapFrame 定位 magic 区分 SysCallEntry/SysCallExit。

## 新增

- Hook NtDeviceIoControlFile 过滤 NSI 查询，隐藏 netstat/TCPView
- ETW Provider Callback hook

```c
AddHideRule(0, 0, 0, HTONS(4444));  // 隐藏远程端口
```

## 参考

- https://github.com/everdox/InfinityHook
- https://github.com/FiYHer/InfinityHookPro
- https://github.com/Wanhu-Nie/etw_hacker
- https://bbs.kanxue.com/thread-289632.htm
