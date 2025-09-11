---
tags:
  - pwn
  - pwn/technique
  - pwn/kernel
---
# Description
Dirty pagetable is a technique that provides an arbitrary read/write primitive that can be used to essentially read from/write to pages regardless of permissions. It leverages a UAF on a pagetable page to manipulate a PTE for arbitrary read/write. It also inspired [[Dirty Pagedirectory]].
# Attack
1. Achieve a UAF on a kmalloc object.

Use a heap vulnerability to get a UAF on a victim object allocated by kmalloc in some kernel slab.

2. Induce the page allocator to reclaim the victim slab.

Empty the victim slab by freeing the rest of the objects in the slab, and then induce the kernel's page allocator to reclaim the victim slab.

3. Heap spray page tables to achieve overlapping allocations between a user page table and the user-controlled allocation.

Assume we are attempting to spray $n$ page tables. First, we mmap $n \cdot 2 \text{ MiB}$. Then, we need to execute a write operation every 0x200000 bytes from the start virtual address to allocate all the user page tables. We will write the same bytes to each address in preparation for step 5.

4. Construct an arbitrary write primitive for manipulating the UAF on the PTE.

Self-explanatory. Find a path in the kernel to writing bytes to the victim object.

5. Identify the corresponding virtual address for the victim object.

This can be done by simply writing a fake PTE to the victim object that points to a physical kernel address. Then, we just read from each virtual address. If the bytes are different from expected (what was written in step 3), this is the corresponding virtual address.

6. Fake PTE to arbitrarily patch the kernel and achieve root.

Modify PTEs in the victim object to provide an arbitrary read/write primitive. In particular, we can patch the kernel RO sections (such as text, RO data) to enable elevating to root privileges.
# References
1. https://yanglingxi1993.github.io/dirty_pagetable/dirty_pagetable.html