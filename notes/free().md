---
tags:
  - pwn
  - pwn/heap
  - pwn/code
---
# Bins
## tcache
[[tcache]]
## fastbin
[[fastbin]]
- Freed chunks cannot be merged/coalesced *until* [[malloc_consolidate()]] is called.
## small bin
- Freed chunks can be merged/coalesced
## large bin
- Freed chunks can be merged/coalesced
## unsorted bin
The unsorted bin is a doubly linked list for any chunk size. Chunks that don't go to [[#tcache]] or [[#fastbin]] go to the unsorted bin *first*. Only later, after another call to [[malloc()]] occurs, do the chunks of the unsorted bin get sorted into their respective small and large bins. A chunk in the unsorted bin contains a pointer to the [[main arena]], which is located in the [[LIBC]]. In other words, successfully getting a chunk into the unsorted bin and subsequently reading the data in the chunk is equivalent to **leaking LIBC**. A chunk will be put into the unsorted bin if one of the following conditions are satisfied:
- A bin of size > <abbr title="0x400">tcache_max</abbr> is allocated.
- Adjacent chunks are merged/coalesced ([[#small bin]]/[[#large bin]] only).
- A bin of size > <abbr title="0x58">fastbin_max</abbr> is allocated AND [[#tcache]] is full for that bin size.
- [[malloc_consolidate()]] is called, resulting in adjacent [[#fastbin]] chunks being merged and placed into the unsorted bin.
## Other notes about bins
For information on how the bins are stored in memory, see [[malloc_state#Description#bins|this section of malloc_state]].
# Special Chunks
- [[top chunk]]
- [[last remainder chunk]]