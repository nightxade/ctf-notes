---
tags:
  - pwn/technique
  - pwn/heap
---
# Description
The top chunk, a.k.a. the **wilderness**, borders the end of the heap. In essence, it is an always-existing chunk with the maximum chunk address on the heap. Memory is split off from the top chunk if there are no freed chunks to service an allocation request. The top chunk may also be expanded if it is not large enough. See [[malloc()]] for a more detailed explanation of when the top chunk is used.
# Techniques
## Corrupt top chunk size
Useful for [[#Freeing top chunk]], [[House of Orange]], and [[House of Tangerine]]. Must be [page-aligned](https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/malloc.c#L2599), i.e. ends in `0x000`.
## Freeing top chunk
> [!todo]

