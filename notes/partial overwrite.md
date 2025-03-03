---
tags:
  - pwn
  - "#pwn/address-randomization"
  - pwn/technique
---
# Description
A partial overwrite involves overwriting an address incompletely/partially, primarily because the most significant bytes of the desired address to write are unknown as a result of *[[address randomization]]*. It may also be because an attacker does not possess enough write space to fully overwrite the address.