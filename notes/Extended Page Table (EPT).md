---
tags:
  - pwn
  - pwn/virtualization
---
# Description
Extended page tables facilitate address translation for virtual machines. Essentially, the guest OS has its own guest 4-level page table that translates Guest Virtual Addresses (GVA) to Guest Physical Addresses (GPA). However, since hypervisor memory is not visible to the guest OS, the GPA must be converted to a Host Physical Address (HPA). In fact, because the guest page table, at each level, points to the *GPA* of the next level of the page table, requires a GPA $\to$ HPA translation at every level. Thus, a typical memory access in the guest (disregarding caches and TLBs) requires a total of 25 memory accesses, as displayed in the diagram below.

![[EPT address translation.png|700]]
