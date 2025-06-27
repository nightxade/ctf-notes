---
tags:
  - pwn/heap
  - pwn/code
---
# Algorithm
> Note that realloc of NULL and realloc to zero size are handled separately and as per the relevant specs.
> 
> In a nutshell, realloc works like this:
> 
> _For MMAP'd chunks..._
> 
> Allocations that are serviced via individual mmap calls (i.e. large ones) are realloc'd by mremap() if available, which may or may not result in the new memory being at a different address than the old memory, depending on what the kernel does.
> 
> If the system does not support munmap() and the new size is smaller than the old size, nothing happens and the old address is returned, else a malloc-copy-free happens.
> 
> _For arena chunks..._
> 
> - If the size of the allocation is being reduced by enough to be "worth it", the chunk is split into two chunks. The first half (which has the old address) is returned, and the second half is returned to the arena as a free chunk. Slight reductions are treated as "the same size".
> - If the allocation is growing, the next (adjacent) chunk is checked. If it is free, or the "top" block (representing the expandable part of the heap), and large enough, then that chunk and the current are merged, producing a large-enough block which can be possibly split (as above). In this case, the old pointer is returned.
> - If the allocation is growing and there's no way to use the existing/following chunk, then a malloc-copy-free sequence is used.

[source](https://sourceware.org/glibc/wiki/MallocInternals)
