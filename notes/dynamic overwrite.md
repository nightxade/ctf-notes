---
tags:
  - pwn/technique
---
# Description
Overwriting the address of the [[ELF#.fini|.fini]] section, which is registered in the [[ELF#.dynamic|.dynamic]] section, with some gadget/function address, will cause the program to call this address when **the main function returns**.
# Links
https://thibaut.sautereau.fr/2016/09/09/bypassing-aslr-overwriting-the-dynamic-section/