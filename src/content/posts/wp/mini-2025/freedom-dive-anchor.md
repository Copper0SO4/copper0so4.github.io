---
title: "FREEDOM Dive↓ Anchor"
published: 2026-10-24
description: "使用 GDB 查看程序给出的内存地址。"
tags: ["CTF", "Vidar-Team", "HGAME mini 2025", "Pwn", "GDB"]
category: "CTF Writeup"
draft: false
lang: "zh_CN"
---

> Diving to the abyss......
> Wait！！ there is an anchor ？

## 运行结果：
```text
========================================
                 Anchor                 
========================================

an anchor has been dropped into the abyss.
it landed at 0x404080

========================================
```

	直接用gdb查看对应地址即可
```gdb
Using host libthread_db library "/usr/lib/libthread_db.so.1".
========================================
                 Anchor                 
========================================

an anchor has been dropped into the abyss.
it landed at 0x404080

========================================

Breakpoint 1, 0x00007ffff7c9e510 in getchar () from /usr/lib/libc.so.6
(gdb) x/s 0x404080
0x404080 <secret>:	"[FLAG REDACTED]"

```
