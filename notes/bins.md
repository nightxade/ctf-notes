---
tags:
  - pwn/heap
  - pwn/code
---
# bins
## tcache
- Per-thread cache for bins of sizes $16,24,\dots,1024$.
- Each bin is a singly-linked list (LIFO) with *a maximum of <abbr title="7">tcache_count</abbr> chunks allowed*.
- Freed chunks cannot be merged. in fact, the **P** (`PREV_INUSE`) flag of the chunk after a freed fastbin chunk is actually set to 1 to indicate that the fastbin cannot be coalesced with adjacent chunks.
- The `chunk->next` pointer of freed chunks undergoes [[safe linking]], which essentially mangles
### Techniques
- [[tcache poisoning]] 
## fastbin
- Faster bins (mainly via no coalescing) of sizes $16, 24,\dots,88$.
- Each bin is a singly-linked list (LIFO).
- Chunks in fastbins may be moved to other bins as needed.
- Freed chunks cannot be merged/coalesced *until* [[malloc_consolidate()]] is called. in fact, the **P** (`PREV_INUSE`) flag of the chunk after a freed fastbin chunk is actually set to 1 to indicate that the fastbin cannot be coalesced with adjacent chunks.
> from glibc source: chunks in fastbins are treated as allocated chunks from the	point of view of the chunk allocator.  they are consolidated with their neighbors only in bulk, in malloc_consolidate.
## small bin
- Small bins of sizes $16,24,\dots,504$.
- Each bin is a doubly-linked list (FIFO).
- Freed chunks are merged/coalesced with adjacent small/large bin chunks whenever they are added to this bin
- The first and last chunk in each small bin contain pointers to the [[main arena]] (since it is a doubly-linked list), which is located in the [[LIBC]]. In other words, successfully getting a chunk into the unsorted bin and subsequently reading the data in the chunk is equivalent to **leaking libc**. %% #pwn/libc-leak %%
## large bin
- Large bins of sizes with variable ranges (e.g., 1st bin is $512-568$ bytes).
- Each bin is a doubly-linked list, with insertion/deletion occurring at any point in the list.
- It may be necessary to split a large bin chunk into two chunks when allocating a new chunk (one is desired size, one is remainder).
- **!!!** Since it's required to find a best fit within a large bin (since each bin is a range of sizes), large bins are technically two doubly-linked lists, with the second linked list **sorted by size** in *descending order*. This doubly-linked list is maintained by the pointers `fd_nextsize` and `bk_nextsize`, and involves the **first chunk** of every size. It may help to sometimes think of the large bin as a "nested doubly-linked list," with chunks of the same size collectively acting as a single node in the parent doubly-linked list (sorted-by-size).
- Freed chunks are merged/coalesced with adjacent small/large bin chunks whenever they are added to this bin
- The first and last chunk in each large bin contain pointers to the [[main arena]] (since it is a doubly-linked list), which is located in the [[LIBC]]. In other words, successfully getting a chunk into the unsorted bin and subsequently reading the data in the chunk is equivalent to **leaking libc**. %% #pwn/libc-leak %%
![[largebin_nextsize.png|750]]
## unsorted bin
- The unsorted bin is a doubly linked list for any chunk size.
- Chunks that don't go to [[#tcache]] or [[#fastbin]] go to the unsorted bin *first*. Only later, after another call to [[malloc()]] occurs, do the chunks of the unsorted bin get sorted into their respective small and large bins.
- The first and last chunk in the unsorted bin contain pointers to the [[main arena]] (since it is a doubly-linked list), which is located in the [[LIBC]]. In other words, successfully getting a chunk into the unsorted bin and subsequently reading the data in the chunk is equivalent to **leaking libc**. %% #pwn/libc-leak %%
- A chunk will be put into the unsorted bin if one of the following conditions are satisfied:
	- a bin of size > <abbr title="0x400">tcache_max</abbr> is allocated.
	- adjacent chunks are merged/coalesced ([[#small bin]]/[[#large bin]] only).
	- a bin of size > <abbr title="0x58">fastbin_max</abbr> is allocated and [[#tcache]] is full for that bin size.
	- [[malloc_consolidate()]] is called, resulting in adjacent [[#fastbin]] chunks being merged and placed into the unsorted bin.
### Techniques
- If allocations are size-constrained (**Nahamcon 2025/pwn/found_memory**):
	1. Exploit an arbitrary write to overwrite a chunk header and make it a much larger chunk.
	2. Make enough allocations/exploit an arbitrary write to ensure there is a chunk located at the end of your new large chunk with the **P** flag set to 1.
	3. Free the chunk
## Other notes about bins
For information on how the bins are stored in memory, see [[malloc_state#Description#bins|this section of malloc_state]].