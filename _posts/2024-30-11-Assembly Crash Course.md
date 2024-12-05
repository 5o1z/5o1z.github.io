---
title: Assembly Crash Course
description: Practice for NASM
author: 5o1z
date: 2024-11-30 9:41 +0700
categories: [Practice, Pwn College]
tags: [rev, pwn, pwntools, code]
image:
  path: /assets/img/Assembly-Crash-Course/Assembly_Language.png
---
## set-register

```python
from pwn import *

p = process(['/challenge/./run'])

code = asm('mov rdi,0x1337', arch='amd64', os='linux')

 p.send(code)
 p.interactive()
```

## set-multiple-registers

```python
from pwn import *

p = process(['/challenge/./run'])

code = asm('''
 mov rax, 0x1337
 mov r12, 0xCAFED00D1337BEEF
 mov rsp, 0x31337
''', arch='amd64', os='linux)

 p.send(code)
 p.interactive()
```

## add-to-register

```python
from pwn import *

p = process(['/challenge/./run'])

code = asm('''
 add rdi, 0x331337
''', arch='amd64', os='linux)

 p.send(code)
 p.interactive()
```

## linear-equation-registers

```python
from pwn import *

p = process(['/challenge/./run'])

code = asm('''
 mov rax, rdi
 imul rax,rsi
 add rax, rdx
''', arch='amd64', os='linux)

 p.send(code)
 p.interactive()
```

## integer-division

```python
from pwn import *

p = process(['/challenge/./run'])

code = asm('''
 mov rax,rdi
 div rsi
''', arch='amd64', os='linux)

 p.send(code)
 p.interactive()
```

## modulo-operation

> Modulo in assembly is another interesting concept!
>
> x86 allows you to get the remainder after a `div` operation.
>
> For instance: `10 / 3` results in a remainder of `1`.
>
> The remainder is the same as modulo, which is also called the "mod" operator.
>
> In most programming languages, we refer to mod with the symbol `%`.

The remainder of the division will be stored in **rdx** if it is **64bit** and **edx** if it is **32bit**

The problem requires the remainder to be stored in rax **`mov rax,rdx`**

```python
from pwn import *

p = process(['/challenge/./run'])

code = asm('''
        mov rax,rdi
        div rsi
        mov rax,rdx
''',arch = 'amd64',os = 'linux')

p.send(code)
p.interactive()
```

## set-upper-byte

```
MSB                                    LSB
+----------------------------------------+
|                   rax                  |           <- 64 bit (8 bytes)
+--------------------+-------------------+
                     |        eax        |           <- 32 bit (4 bytes)
                     +---------+---------+
                               |   ax    |           <- 16 bit (2 bytes)
                               +----+----+
                               | ah | al |           <- 8 bit  (1 byte)
                               +----+----+
```

* MSB = Most Significant Byte
* LSB = Least Significant Byte

```python
from pwn import *

p = process(['/challenge/./run'])

code = asm('''
        mov ah, 0x42
''',arch = 'amd64',os = 'linux')

p.send(code)
p.interactive()
```

## effecient-modulo

> If we have `x % y`, and `y` is a power of 2, such as `2^n`, the result will be the lower `n` bits of `x`

Simple explanation:

* For **`x % 256`**, the value of **256** is **282^8**. This means that the result of the operation **`rdi % 256`** is the value of the lowest 8 bits of the **`rdi`** register.
* Similarly, for **`x % 65536`**, the value of **65536** is **2162^16**. The result of **`rsi % 65536`** is the value of the lowest 16 bits of the **`rsi`** register

```python
from pwn import *

p = process(['/challenge/./run'])

code = asm('''
    mov    al,dil # 8-bit thấp của rdi
    mov    bx,si  # 16-bit của rsi
    ''', arch = 'amd64',os = 'linux')

p.send(code)
p.interactive()
```

## byte-extraction

> Shifting bits around in assembly is another interesting concept!
>
> x86 allows you to 'shift' bits around in a register.
>
> Take, for instance, `al`, the lowest 8 bits of `rax`.
>
> The value in `al` (in bits) is:
>
> ```nasm
> rax = 10001010
> ```
>
> If we shift once to the left using the `shl` instruction:
>
> ```nasm
> shl al, 1
> ```
>
> The new value is:
>
> ```nasm
> al = 00010100
> ```
>
> Everything shifted to the left, and the highest bit fell off while a new 0 was added to the right side.
>
> You can use this to do special things to the bits you care about.
>
> Shifting has the nice side effect of doing quick multiplication (by 2) or division (by 2), and can also be used to compute modulo.

```python
from pwn import *

p = process(['/challenge/./run'])

code = asm('''
    int3
    shr rdi, 32
    mov al, dil
    int3
    ''', arch = 'amd64',os = 'linux')

p.send(code)
p.interactive()
```

```nasm
We will now set the following in preparation for your code:
  rdi = 0x8b2405d45d514a80

You ran me without an argument. You can re-run with `/challenge/run /path/to/your/elf` to input an ELF file, or just give me your assembled and extracted code in bytes (up to 0x1000 bytes):
Executing your code...
---------------- CODE ----------------
0x400000:    int3
0x400001:    shr       rdi, 0x20
0x400005:    mov       al, dil
0x400008:    int3
--------------------------------------
+--------------------------------------------------------------------------------+
| Registers                                                                      |
+-------+----------------------+-------+----------------------+------------------+
|  rax  |  0x0000000000000000  |  rbx  |  0x0000000000000000  |                  |
|  rcx  |  0x0000000000000000  |  rdx  |  0x0000000000000000  |                  |
|  rsi  |  0x0000000000000000  |  rdi  |  0x8b2405d45d514a80  |                  |
|  rbp  |  0x0000000000000000  |  rsp  |  0x00007fffff200000  |                  |
|  r8   |  0x0000000000000000  |  r9   |  0x0000000000000000  |                  |
|  r10  |  0x0000000000000000  |  r11  |  0x0000000000000000  |                  |
|  r12  |  0x0000000000000000  |  r13  |  0x0000000000000000  |                  |
|  r14  |  0x0000000000000000  |  r15  |  0x0000000000000000  |                  |
|  rip  |  0x0000000000400001  |       |                      |                  |
+---------------------------------+-------------------------+--------------------+
| Stack location                  | Data (bytes)            | Data (LE int)      |
+---------------------------------+-------------------------+--------------------+
+---------------------------------+-------------------------+--------------------+
| Memory location                 | Data (bytes)            | Data (LE int)      |
+---------------------------------+-------------------------+--------------------+
|    0x0000000000404000 (+0x0000) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
|    0x0000000000404008 (+0x0008) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
|    0x0000000000404010 (+0x0010) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
|    0x0000000000404018 (+0x0018) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
+---------------------------------+-------------------------+--------------------+
+--------------------------------------------------------------------------------+
| Registers                                                                      |
+-------+----------------------+-------+----------------------+------------------+
|  rax  |  0x00000000000000d4  |  rbx  |  0x0000000000000000  |                  |
|  rcx  |  0x0000000000000000  |  rdx  |  0x0000000000000000  |                  |
|  rsi  |  0x0000000000000000  |  rdi  |  0x000000008b2405d4  |                  |
|  rbp  |  0x0000000000000000  |  rsp  |  0x00007fffff200000  |                  |
|  r8   |  0x0000000000000000  |  r9   |  0x0000000000000000  |                  |
|  r10  |  0x0000000000000000  |  r11  |  0x0000000000000000  |                  |
|  r12  |  0x0000000000000000  |  r13  |  0x0000000000000000  |                  |
|  r14  |  0x0000000000000000  |  r15  |  0x0000000000000000  |                  |
|  rip  |  0x0000000000400009  |       |                      |                  |
+---------------------------------+-------------------------+--------------------+
| Stack location                  | Data (bytes)            | Data (LE int)      |
+---------------------------------+-------------------------+--------------------+
+---------------------------------+-------------------------+--------------------+
| Memory location                 | Data (bytes)            | Data (LE int)      |
+---------------------------------+-------------------------+--------------------+
|    0x0000000000404000 (+0x0000) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
|    0x0000000000404008 (+0x0008) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
|    0x0000000000404010 (+0x0010) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
|    0x0000000000404018 (+0x0018) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
+---------------------------------+-------------------------+--------------------+
```
