---
tags:
  - pwn
  - pwn/technique
  - pwn/kernel
---
# Description
Dirty pagedirectory is a technique that provides an arbitrary read/write primitive that can be used to essentially read from/write to pages regardless of permissions.

> "The Dirty Pagedirectory technique allows unlimited, stable read/write to any memory page based on physical addresses. It can bypass permissions by setting its own permission flags. This allows our exploit to write to read-only pages like those containing `modprobe_path`." \[1\]

It is inspired by [[Dirty Pagetable]]. Essentially, it involves overlapping a Page Middle Directory and Page Table Entry. (Or, alternatively, you could overlap a PUD and PMD, or PGD and PUD; but these can cause issues with memory).

> "The only difference is the amount of pages simulationously mirrored: 1GiB pages with PTE+PMD, 512GiB with PUD+PMD, and presumably 256TiB with PGD+PUD (if this is even possible). Keep in mind that this has impact on memory usage, and the system may go OOM with too much memory mirrored." \[1\]
# Attack
The following attack will be explained from the perspective of overlapping PUD and PMD (mainly because \[1\] provides the diagram for that).

![[dirty-pagedirectory.png|750]]
1. Overlap PUD and PMD.

We first have to force a PUD and PMD to the same kernel address. In the above diagram, this is PUD Y and PMD X. In \[1\], they leverage a double free bug in the kernel (followed by spraying pagetables) to achieve this; but, other methods may work too.

2. Write a fake PTE to an address stored in the PUD X hierarchy.

Since PMD X overlaps with PUD Y, the page that the user writes to is, in fact, overlapping with PTE Y. In other words, when we write to the "userland" page that's mapped under PUD X, we actually overwrite PTE Y! This allows us to arbitrarily modify PTE Y. With this, we can control not only the physical page we want to write to but also the permissions of the page.

3. Flush the [[TLB]].

Since the PTE was changed from userland, we need to flush the TLB (translation lookaside buffer) so the previously cached page translation does not stay. After this, we can [(1)](https://pwning.tech/nftables/#48-dealing-with-physical-kaslr) leak physical KASLR base by brute forcing the search space, (2) leak the target physical address by scanning the ~80Mib of physical kernel memory for data patterns or use hardcoded offsets, and (3) arbitrarily read/write data to the target address! Most commonly, we can just overwrite `modprobe_path` to perform the [[modprobe_path]] attack.

> "I have used this technique to bypass a lot of mitigations currently in the kernel (among others: virtual [[KASLR]], [[KPTI]], [[SMAP]], [[SMEP]], and [[modprobe_path#CONFIGSTATICUSERMODEHELPER|`CONFIG_STATIC_USERMODEHELPER`]]), albeit other mitigations are bypassed in the PoC exploit with a little redneck engineering." \[1\]

# References
1. https://pwning.tech/nftables/