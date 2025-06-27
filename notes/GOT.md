---
tags:
  - bin/elf
---
# Description
The **GOT** refers to the **Global Offset Table**. When the program calls a linked library function, a stub function in the [[PLT]] is called, which in turn calls the address in the memory assigned to this function in the GOT. This table contains the addresses of dynamically linked library (often [[LIBC]]) functions, which are *lazily resolved/linked* at runtime when a library function is first called. Before it is first called, the GOT entry contains the address of some code used for lazy resolution. See [[lazy resolution]] for more details.
# Notes
The GOT can commonly be attacked through a [[GOT overwrite]] attack, provided [[RELRO#Full RELRO|Full RELRO]] is not enabled.