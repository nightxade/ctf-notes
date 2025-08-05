---
tags:
  - pwn/kernel
  - pwn/mitigation
---
# Description
KPTI, Kernel Page Table Isolation, was a mitigation introduced for the Linux kernel to mitigate [[Meltdown]]-class microarchitectural attacks. Its design is heavily inspired by the KAISER paper. Essentially, KPTI separates the kernel and user page table entries, essentially unmapping kernel addresses during userspace execution. Notably, though, a few kernel pages remain in the page table for users for the purpose of context switching to the kernel, i.e. system call and interrupt handling. When a kernel context switch happens, the kernel simply changes the register pointing to the top level page table, i.e. CR3 (holds physical address of Page Global Directory).
# Attack
- [[KPTI Trampoline]]
- [[EntryBleed]] (patched)
# References
1. William Liu, Joseph Ravichandran, and Mengjia Yan. 2023. EntryBleed: A Universal KASLR Bypass against KPTI on Linux