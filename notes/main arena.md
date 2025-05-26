---
tags:
  - pwn
  - pwn/heap
  - pwn/code
---
# Description
The main arena stores information about the heap. It is implemented via the [[malloc_state]] struct, and is located before the [[LIBC]]. (Note, though, that leaking the main arena address allows **leaking LIBC**). There is typically one main arena per process, though multithreaded processes may have more.
# Attacks
- [[House of Gods]]