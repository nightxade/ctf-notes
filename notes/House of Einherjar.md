---
tags:
  - pwn/heap
  - pwn/technique
---
# Description
The **House of Einherjar** is a technique that leverages an [[off-by-one]] overflow on a buffer on the heap (most commonly a *null byte* overflow) to eventually gain an arbitrary chunk allocation.

TL;DR:
1. We forge a fake freed, doubly-linked chunk
2. Free an adjacent chunk to coalesce it with our fake chunk
3. Our coalesced chunk lands in the [[bins#unsorted bin|unsorted bin]] ([[LIBC]] leak)
4. Perform [[tcache poisoning]] with your new [[overlapping chunks]]
# Attack
## Requirements
- Heap leak %% #pwn/heap-leak %%
- [[off-by-one]] overflow
## Result
- [[overlapping chunks]] / [[use after free|UAF]]
- [[tcache poisoning]]
- [[LIBC]] leak %% #pwn/libc-leak %%
## Process
### Parameters/Constraints
- Chunk `a` size: `sz_a`, can be any
- Chunk `b` size (desired tcache poisoning size): `sz_b`, must be tcache sized
- Chunk `c` size: `sz_c`, must be greater than <abbr title="0x58">fastbin_max</abbr> so it will go to [[bins#unsorted bin|unsorted bin]]
- Target pointer for allocation, `target`
### Steps
1. Fill [[bins#tcache|tcache]] for `sz_c` (alternatively, this may be done after allocating `a,b,c`)
   ```c
	for (int i = 0; i < 7; i++) {
		malloc(sz_c)
	}
	
	malloc(0x18) // malloc once more to ensure no coalescing with top chunk
	
	for (int i = 0; i < 7; i++) {
	malloc(sz_c)
	}
	```
2. 
# Examples
- smiley CTF 2025 / pwn / limit
# References
- [how2heap](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/house_of_einherjar.c) 