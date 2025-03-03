---
tags:
  - "#pwn"
  - pwn/full-relro
  - pwn/technique
---
# Description
Overwrite the *[[GOT]]* of a linked *[[LIBC]]* function $f$ with your own address of gadgets, other functions, etc. The technique requires Full *[[RELRO]]* to be **disabled**.
# Notes
- If *[[ASLR]]* is enabled, but you want to link a LIBC address to $f$, you can perform a *[[partial overwrite]]* of the LIBC address of $f$. This may require $4$ or $12$ bits of *[[brute force]]*, if you need to overwrite $2$ or $3$ bytes of the least significant bytes, respectively.
- If you can write enough bytes into the GOT, you can write a *[[ROP]]* chain into it.
	- This can cause issues if any other LIBC functions linked in the GOT are called during program execution, and you overwrote that function's GOT entry with your ROP chain.