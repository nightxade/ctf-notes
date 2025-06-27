---
tags:
  - pwn/mitigation
---
# Description
**RELRO**, a.k.a. Relocation Read-Only, was a protection that makes certain sections of a binary read-only. It was introduced to increase the difficulty of performing a [[GOT overwrite]] attack.
## Partial RELRO
This is the most common protection, and is the default setting for [[gcc]]. The only change it makes is forcing the [[GOT]] to come before the [[ELF#.bss|.bss]] section in memory. This ensures that it is not possible to perform a [[buffer overflow]] attack on a .bss variable and subsequently overwrite the GOT.
## Full RELRO
This is a more comprehensive protection, in which the GOT itself is made read-only. This makes a GOT overwrite attack *impossible*. However, this is not a default gcc setting since it introduces a performance overhead for program startup time. This is because the GOT is typically lazily resolved (see [[GOT]] for brief explanation), and therefore a read-only GOT forces the process to resolve all linked library symbols at program startup.
# References
- https://ctf101.org/binary-exploitation/relocation-read-only/