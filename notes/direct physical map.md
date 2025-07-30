---
tags:
  - pwn/kernel
---
# Description
The direct physical map is a essentially a virtual mapping of all physical addresses. It is present within the **Linux** kernel address space, and begins at `0xffff_8800_0000_0000` if the direct-physical map is not randomized or at `page_offset_base` if it is. Essentially, a physical address `x` can be read by simply adding `x` to the base of the direct-physical map.