---
tags:
  - pwn/heap
  - pwn/code
---
# bins
## tcache
- Per-thread cache for bins of sizes $16,24,\dots,1024$ (`0x400`).
- Each bin is a singly-linked list (LIFO) with *a maximum of <abbr title="7">tcache_count</abbr> chunks allowed*.
- Freed chunks cannot be merged. in fact, the **P** (`PREV_INUSE`) flag of the chunk after a freed fastbin chunk is actually set to 1 to indicate that the fastbin cannot be coalesced with adjacent chunks.
- The `chunk->next` pointer of a tcache chunk undergoes [[safe linking]], which essentially mangles the pointer. This can be easily reversed with a single leak of a `chunk->next` pointer. (i.e., after reading a mangled pointer you can decrypt it). Notably, `chunk->next` is *not* cleared when a tcache chunk is reallocated, meaning reading from that chunk may allow a leak.
- The `chunk->key` pointer is set to some random entropy (that is the *same **process-wide***) upon freeing a chunk into tcache. This is actually an update from **glibc 2.34**. Prior to 2.34, `chunk->key` was set to the address of the `tcache_perthread_struct`. When allocating from tcache, `chunk->key` is cleared! That is, it'll just write a null byte into `chunk->tcache`. Note the following [code](https://elixir.bootlin.com/glibc/glibc-2.41/source/malloc/malloc.c#L3129) from 2.34:
```c
/* Process-wide key to try and catch a double-free in the same thread.  */
static uintptr_t tcache_key;

/* The value of tcache_key does not really have to be a cryptographically
   secure random number.  It only needs to be arbitrary enough so that it does
   not collide with values present in applications.  If a collision does happen
   consistently enough, it could cause a degradation in performance since the
   entire list is checked to check if the block indeed has been freed the
   second time.  The odds of this happening are exceedingly low though, about 1
   in 2^wordsize.  There is probably a higher chance of the performance
   degradation being due to a double free where the first free happened in a
   different thread; that's a case this check does not cover.  */
static void
tcache_key_initialize (void)
{
  /* We need to use the _nostatus version here, see BZ 29624.  */
  if (__getrandom_nocancel_nostatus_direct (&tcache_key, sizeof(tcache_key),
					    GRND_NONBLOCK)
      != sizeof (tcache_key))
    {
      tcache_key = random_bits ();
#if __WORDSIZE == 64
      tcache_key = (tcache_key << 32) | random_bits ();
#endif
    }
}
```
- As of **glibc 2.42**, tcache now allows larger chunks of up to 4 MB (`0x400000`), in a series of `12` large tcache bins.
  They are not enabled by default. Each large tcache bin holds the next bit of sizes. (e.g. `(0x400, 0x800]`, `(0x800, 0x10000]`, etc.). Each of them holds chunks in sorted order, and chunks are allocated from (`tcache_get_large`) and freed to (`tcache_put_large`) each large tcache bin by linearly iterating through the bin until the first chunk whose size is greater than or equal to the chunk size being allocated/freed. It will fall through to `tcache_get_n`/`tcache_put_n`, where it will be prepended to the bin (`mangled = false`) or inserted into the middle (`mangled = true`), depending on the result of the iteration (`tcache_location_large`).
  > The thread-local cache in malloc (tcache) now supports caching of large blocks.  This feature can be enabled by setting the tunable glibc.malloc.tcache_max to a larger value (max 4194304). Tcache is also significantly faster for small sizes. \[1\]
  
  Tunables are set via [[LIBC_PROBE]], and this one in particular is set in `do_set_tcache_max`.
### Techniques
- [[tcache poisoning]] 
## fastbin
- Faster bins (mainly via no coalescing) of sizes $16, 24,\dots,88$.
- Each bin is a singly-linked list (LIFO).
- Chunks in fastbins may be moved to other bins as needed.
- Freed chunks cannot be merged/coalesced *until* [[malloc_consolidate()]] is called. in fact, the **P** (`PREV_INUSE`) flag of the chunk after a freed fastbin chunk is actually set to 1 to indicate that the fastbin cannot be coalesced with adjacent chunks.
- The `chunk->next` pointer of a fastbin chunk undergoes [[safe linking]] like tcache chunks do..
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
# References
1. https://github.com/bminor/glibc/blob/master/NEWS