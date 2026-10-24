---
title: "tactaen A"
published: 2026-10-24
description: "分析字符串比较，通过 pwntools 发送不可打印字符。"
tags: ["CTF", "Vidar-Team", "HGAME mini 2025", "Pwn", "逆向分析"]
category: "CTF Writeup"
draft: false
lang: "zh_CN"
---

>你遇到了一只奇怪的猫，他在找一些键盘上没有的字符🐈
>(~~IDA may help you~~)


直接看伪代码：

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char s1[10]; // [rsp+6h] [rbp-Ah] BYREF

  setbuf(stream: stdin, buf: nullptr);
  setbuf(stream: stdout, buf: nullptr);
  setbuf(stream: stderr, buf: nullptr);
  printf(format: "Input the secret, and I will give you flag:\n>");
  __isoc99_scanf(a1: "%9s", s1);
  if ( strcmp(s1, s2: "114514") == 0 )
  {
    system(command: "/bin/sh");
    exit(status: 0);
  }
  if ( strcmp(s1, s2: &byte_402049) == 0 )
    printf(format: "[FLAG REDACTED]");
  return 0;
}
```

正常运行程序我们需要输入键盘无法输入的字符，也就是从IDA里直接看0x402049对应的地址：
```
.rodata:0000000000402049 byte_402049     db 11h                  ; DATA XREF: main+AE↑o
.rodata:000000000040204A                 db  45h ; E
.rodata:000000000040204B                 db  14h
.rodata:000000000040204C                 db    0
```
也就是b"\x11\x45\x14\x00"，不过既然直接能看到伪代码了就不管了，直接拿到flag的前半部分就是`[FLAG REDACTED]` ，看到输入114514就是执行shell，可以猜测剩下一半的flag就在远端。

开启remote环境后直接nc连上去
```zsh
❯ nc HOST_REDACTED PORT_REDACTED
Input the secret, and I will give you flag:
>114514
ls
entrypoint.sh
flag.txt
vuln
vuln.c
cat flag.txt
[FLAG REDACTED]
exit
```

拼在一起
`[FLAG REDACTED]`

倘若想要手动触发输出flag，直接使用pwntools发送上述内容就好了
```python
from pwn import *

p = remote("HOST_REDACTED", 0)
p.sendlineafter(b">", b"\x11\x45\x14")
print(p.recvall())
```

得到`b'[FLAG REDACTED]'`
