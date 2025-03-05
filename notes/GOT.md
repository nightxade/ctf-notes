---
tags:
  - pwn
  - bin/elf
---
# Description
The **GOT** refers to the **Global Offset Table**. This table contains the addresses of dynamically linked library (often [[LIBC]]) functions, which are resolved at runtime. When the program calls a linked library function, a stub function in the [[PLT]] is called, which in turn calls the address in the memory assigned to this function in the GOT.
# Notes
The GOT can commonly be attacked through a [[GOT overwrite]] attack, provided Full [RELRO] is not enabled.