---
tags:
  - pwn/mitigation
---
# Description
Address randomization refers to randomizing program addresses, which often forces an attacker to leak an address from the program in order to have knowledge of the program addresses for functions, data, etc.
# Notes
These are the following associated mitigations that add address randomization.
- [[ASLR]] ([[LIBC]])
- [[PIE]] (main program)
- [[KASLR]] (kernel)
