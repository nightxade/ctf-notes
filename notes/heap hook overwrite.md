---
tags:
  - pwn
  - pwn/technique
  - pwn/glibc-2-34
---
# Description
Overwriting a heap function hook, typically `__malloc_hook` or `__free_hook`, with a gadget/function address, causes the program to call said address whenever `malloc` or `free` is called. This has been **patched** as of **GLIBC 2.34**.
# Links
https://www.crow.rip/crows-nest/binexp/heap/house-of-force-i/house-of-force-ii