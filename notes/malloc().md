---
tags:
  - pwn/heap
  - pwn/code
---
# Algorithm
> In a nutshell, malloc works like this:
> 
> - If there is a suitable (exact match only) chunk in the tcache, it is returned to the caller. No attempt is made to use an available chunk from a larger-sized bin.
> - If the request is large enough, mmap() is used to request memory directly from the operating system. Note that the threshold for mmap'ing is dynamic, unless overridden by `M_MMAP_THRESHOLD` (see mallopt() documentation), and there may be a limit to how many such mappings there can be at one time.
> - If the appropriate fastbin has a chunk in it, use that. If additional chunks are available, also pre-fill the tcache.
> - If the appropriate smallbin has a chunk in it, use that, possibly pre-filling the tcache here also.
> - If the request is "large", take a moment to take everything in the fastbins and move them to the unsorted bin, coalescing them as you go. See [[malloc_consolidate()]].
> - Start taking chunks off the unsorted list, and moving them to small/large bins, coalescing as you go (note that this is the **only** place in the code that puts chunks into the small/large bins). If a chunk of the right size is seen, use that.
> - If the request is "large", search the appropriate large bin, and successively larger bins, until a large-enough chunk is found.
> - If we still have chunks in the fastbins (this may happen for "small" requests), consolidate those and repeat the previous two steps. Again, [[malloc_consolidate()]].
> - Split off part of the "top" chunk, possibly enlarging "top" beforehand.
> 
> For an over-aligned malloc, such as valloc, pvalloc, or memalign, an overly-large chunk is located (using the malloc algorithm above) and divided into two or more chunks in such a way that most of the chunk is now suitably aligned (and returned to the caller), and the excess before and after that portion is returned to the unsorted list to be re-used later.

[source](https://sourceware.org/glibc/wiki/MallocInternals)
# Techniques
> [!warning] `malloc()` does NOT clear `chunk->next`, only `chunk->key`!!! You can get a leak from allocating a previously freed chunk and printing from it!!
> Only [[calloc()]] initializes memory to all null bytes.

> [!info]
> The previous fact allows us to actually leak [[PIE]] (elf base) and [[ASLR]] (LIBC base) from (most likely) [[LIBC]] even without a [[use after free|UAF]] on chunks allocated in [[LIBC]]. See Smiley CTF 2025 / pwn / limit for more details.

