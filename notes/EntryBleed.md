---
tags:
  - pwn/microarchitecture/cache
---
# Description
EntryBleed is a microarchitectural side channel attack that bypasses [[KASLR]] even with [[KPTI]] enabled in Linux on Intel chips. It exploits a TLB prefetch side channel and the limited entropy of (non-fine-grained) KASLR.
# Vulnerability
## KPTI
Linux's KPTI mitigation was introduced to prevent [[Meltdown]]-class attacks. In short, it separates the userspace and kernelspace address spaces by requiring distinct page tables. Notably, however, a small subset of kernel addresses are mapped in into the userland page tables: a "**trampoline region**". See [[KPTI]] for more details.
## Prefetch Side Channel
The [[TLB]], Translation Lookaside Buffer, is essentially a cache for virtual to physical page address translations. The family of prefetch instructions allows a user to preemptively cache a virtual address in the TLB. Notably, a prefetch instruction will take measurably more CPU cycles if the prefetched address is not mapped in the TLB. And, critically, prefetching an invalid or kernel memory address will not cause any exceptions.
## KASLR Entropy
With KASLR enabled, the kernel space base address is randomized. However, considering the kernel space's required alignment (2MB) and its allowed virtual address range, the total entropy is only 9 bits. Moreover, the offset of the trampoline region to the kernel base remains constant across user and kernel space.
# Attack
## Step 1: Cache the Trampoline
First, an attacker caches the syscall handler address, `entry_SYSCALL_64`, (or, rather, the address of the corresponding page) in the TLB. This is done by simply executing a syscall from userspace, as this will jump to the trampoline and trigger a context switch to kernel space. Typically, the context switch requires switching the CR3 register between the userspace and kernelspace root page table, which flushes the entire TLB. However, after returning to userspace, there are still some epilogue instructions in the trampoline that must be executed. Notably, the CR3 register must be switched back to point to the user space root page table; thus, the trampoline page remains cached in the TLB regardless. Additionally, this page is marked with the global bit for performance, which actually ensures that this page is *not flushed from the TLB* during a CR3 switch.
## Step 2: Guess KASLR Base
The attacker now guesses a random possible KASLR base. It then attempts to prefetch the address of `entry_SYSCALL_64` according to its guess. If the guess was correct, the instruction latency should be very quick, since the address is already cached in the TLB. If the guess was incorrect, the instruction will take many more CPU cycles. (Measure with `rdtsc`).
## Step 3: Repeat
Simply repeat steps 1 and 2 for all possible KASLR base addresses. The shortest measured instruction latency will confirm the correct guess.
# Mitigations
As of today (August 1st, 2025), I'm not aware of any widely deployed mitigations. The paper does suggest some solutions, such as making the offsets of the trampoline to the kernel base nonconstant and strengthening FG-KASLR(?).
# References
1. William Liu, Joseph Ravichandran, and Mengjia Yan. 2023. EntryBleed: A Universal KASLR Bypass against KPTI on Linux
2. https://www.willsroot.io/2022/12/entrybleed.html