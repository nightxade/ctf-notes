---
tags:
  - pwn
  - pwn/heap
  - pwn/code
---
[malloc_consolidate](https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L4714) essentially merges all [[free()#Bins#fastbin|fastbin]] chunks with their neighbors, puts them in the [[free()#Bins#unsorted bin|unsorted bin]] and merges them with the [[top chunk]] if possible.

As of glibc version **2.35** it is called only in the following five places:
1. \_int\_malloc: A large sized chunk is being allocated. [glibc](https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L3965).
2. \_int\_malloc: No bins were found for a chunk and top is too small. [glibc](https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L4394). See [[top chunk#Corrupt top chunk size|this]] on how to corrupt top chunk size.
3. \_int\_free: If the chunk size is >= FASTBIN_CONSOLIDATION_THRESHOLD (65536). [glibc](https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L4674).
4. mtrim: Always. [glbc](https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L5041).
5. \_\_libc_mallopt: Always. [glibc](https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L5463).

It is most useful to **leak [[LIBC]]** or induce a **[[double free]]**.
# References
- [how2heap fastbin_dup_consolidate](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/fastbin_dup_consolidate.c)
