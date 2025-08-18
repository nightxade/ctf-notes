---
tags:
  - pwn
  - pwn/kernel
  - pwn/code
---
# Description
The Linux kernel allocates pages primarily in 3 distinct ways.
- The [[buddy allocator]] is invoked with [`alloc_pages`](https://elixir.bootlin.com/linux/v6.16/source/include/linux/gfp.h#L341) and can allocate any page order (0-10) from a global, CPU-independent pool of pages.
- The [[PCP allocator]] (per-CPU allocator) is similarly invoked with [`alloc_pages`](https://elixir.bootlin.com/linux/v6.16/source/include/linux/gfp.h#L341) and can allocate pages of order 0-3 from a per-CPU pool of pages.
\*Note that the PCP allocator was introduced because the buddy allocator *locks* when a CPU is allocating a page from the global pool, blocking other CPUs from allocating pages. The PCP allocator allows for faster page retrieval for smaller page sizes.
- The [[SLAB allocator]] (or, SLUB now) is invoked with [`kmalloc`](https://elixir.bootlin.com/linux/v6.16/source/tools/lib/slab.c#L14) and can allocate pages of order 0-1 from various per-CPU freelists/caches.

![[page allocation order.png|750]] \[1\]

Also, a slightly outdated diagram of page allocation paths during a call to `kmalloc`:

![[page allocation diagram.png|750]] \[1\]
# References
1. https://pwning.tech/nftables/#514-overwriting-modprobepath
2. https://elixir.bootlin.com/linux/v6.16/source