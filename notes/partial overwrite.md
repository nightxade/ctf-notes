---
tags:
  - pwn/address-randomization
  - pwn/technique
---
# Description
A partial overwrite involves overwriting an address incompletely/partially, primarily because the most significant bytes of the desired address to write are unknown as a result of [[address randomization]]. It may also be because an attacker does not possess enough write space to fully overwrite the address.  
## ELF
The base of a program with [[PIE]] protections always ends in 0x000. Main program addresses typically depend on the last 2 bytes  . Therefore, returning to a gadget/function in the main program will typically take 0-4 bits of brute force.
## LIBC
The base of [[LIBC]] also ends in 0x000. However, libc addresses are typically longer, usually depending on the last 3 bytes. Therefore, returning to a gadget/function in libc will take 0-12 bits of brute force  