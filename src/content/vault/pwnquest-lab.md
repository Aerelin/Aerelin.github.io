---
title: "PwnQuest Lab：交互式 Pwn 内存攻防实验室"
created: 2026-11-16
tags: ["CTF", "Pwn", "安全工具"]
---

[PwnQuest Lab](/labs/pwnquest/) 是一个无需安装、打开浏览器即可使用的交互式 Pwn 教学工具。它将栈帧、printf 参数、tcache 链表和内核凭证等抽象概念转化为可操作的内存状态，让每一次成功或失败都有明确的执行过程。

## 立即开始

**[进入 PwnQuest Lab →](/labs/pwnquest/)**

建议使用最新版 Chrome、Edge 或 Firefox。学习进度只保存在当前浏览器中，不会上传任何数据。

![PwnQuest Lab 首页](/labs/pwnquest/preview.png)

## 训练内容

当前 Core Web Edition 包含 6 个模块、20 个关卡：

| 模块 | 主要知识点 |
|---|---|
| 二进制作战基础 | NX、RELRO、ASLR、GOT 读写、libc 基址计算 |
| 栈了个栈 | 精确覆盖、ret2libc、栈对齐、Canary、栈迁移 |
| 字符串迷城 | 位置参数、任意读、`%n` 与 `%hn` 写入 |
| 堆海炼金 | tcache、UAF、Safe-linking、tcache poisoning |
| 深入 Ring 0 | cred、SMEP/SMAP、KASLR、内核 ROP、KPTI |
| 随机的二进制 | 根据保护组合选择完整利用路线 |

## 使用方法

1. 在首页选择训练模块。
2. 阅读关卡目标和 TARGET SNAPSHOT。
3. 填写地址或 payload，或者按顺序排列 gadget 与操作卡片。
4. 通过 EXECUTION TRACE 观察每一步的状态与失败原因。
5. 遇到困难时使用三级提示，通关后查看知识点解释。
6. 在顶栏错题本中复习失败记录，或导出 JSON 学习进度。

## 设计目标

这个项目不仅用于展示漏洞利用结果，更关注利用链为什么成立。例如，它会区分返回地址覆盖不足、Canary 校验失败、ROP 栈未对齐、格式化字符串输出计数错误、Safe-linking 解码错误以及 SMEP 拦截。

线上版本是纯教学模拟器，不会将模拟结果冒充为真实 ELF 利用验证。真实进程执行、GDB、Docker 多 libc 环境与 QEMU 内核调试属于后续本地扩展方向。

**[开始训练 →](/labs/pwnquest/)**
