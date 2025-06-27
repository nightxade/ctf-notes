---
tags:
  - pwn/heap
  - pwn/code
---
# Algorithm
> Note that, in general, "freeing" memory does not actually return it to the operating system for other applications to use. The free() call marks a chunk of memory as "free to be reused" by the application, but from the operating system's point of view, the memory still "belongs" to the application. However, if the top chunk in a heap - the portion adjacent to unmapped memory - becomes large enough, some of that memory may be unmapped and returned to the operating system.
> 
> In a nutshell, free works like this:
> - If there is room in the tcache, store the chunk there and return.
> - If the chunk is small enough, place it in the appropriate fastbin.
> - If the chunk was mmap'd, munmap it.
> - See if this chunk is adjacent to another free chunk and coalesce if it is.
> - Place the chunk in the unsorted list, unless it's now the "top" chunk.
> - If the chunk is large enough, coalesce any fastbins and see if the top chunk is large enough to give some memory back to the system. Note that this step might be deferred, for performance reasons, and happen during a malloc or other call. See [[malloc_consolidate()]].

[source](https://sourceware.org/glibc/wiki/MallocInternals)
# References
- https://ir0nstone.gitbook.io/notes/binexp/heap/bins
- https://sourceware.org/glibc/wiki/MallocInternals