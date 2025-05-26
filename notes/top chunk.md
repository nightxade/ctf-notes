---
tags:
  - pwn
  - pwn/technique
  - pwn/heap
---
# Description
The top chunk, a.k.a. the **wilderness**, borders the end of the heap. In essence, it is an always-existing chunk with the maximum chunk address on the heap. It should never be freed
# Techniques
## Corrupt top chunk size
Useful for [[#Freeing top chunk]], [[House of Orange]], and [[House of Tangerine]]. Must be [page-aligned](https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/malloc.c#L2599)
## Freeing top chunk
> [!todo]

