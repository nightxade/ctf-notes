---
tags:
  - pwn
  - pwn/nx-dep
  - pwn/technique
---
# Description
Shellcode is essentially user-injected machine instructions. ret2shellcode involves **ret**urning or **jmp**ing to the address at which your shellcode is located. It requires [[NX-DEP|NX or DEP]] to be **disabled**.\* It typically requires leaking an address of the segment in which your shellcode is located if [[address randomization]] is **enabled** for that segment.

\* *Exception: if `mprotect()` is used to change memory protections for a section of memory, i.e. make it both writeable and executable, then it is possible to perform ret2shellcode on shellcode written to that section of memory, regardless of NX/DEP being enabled. More generally, the **page** in which the shellcode resides must be executable (this becomes relevant for kernel pwn).*
# Snippets
## shell
```py
sh = bytes(asm('mov rax, 0x68732f6e69622f; push rax; mov rdi, rsp; mov rsi, 0; mov rdx, 0; mov rax, SYS_execve; syscall;'))
```