---
tags:
  - pwn/technique
  - pwn/heap
  - pwn/patch/glibc-2-34
---
# Description
Overwriting a heap function hook (located in [[LIBC]]), typically `__malloc_hook` or `__free_hook`, with a gadget/function address, causes the program to call said address whenever [[malloc()]] or [[free()]] is called. The hook will be called with the same argument of malloc()/free() (e.g., for free(), address of chunk to be freed). This has been patched as of **GLIBC 2.34**.
# Example
Overwrite `__free_hook` with the address of `system`, write `/bin/sh\x00` into a chunk, and free that chunk $\to$ `system("/bin/sh")` is called.
# Links
https://www.crow.rip/crows-nest/binexp/heap/house-of-force-i/house-of-force-ii