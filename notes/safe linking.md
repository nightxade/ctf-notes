---
tags:
  - pwn/heap
  - pwn/mitigation
  - pwn/patch/glibc-2-32
---
# Description
Safe linking was a protection introduced in **GLIBC 2.32** to make corrupting the singly-linked lists, i.e. [[bins#tcache|tcache]] and [[bins#fastbin|fastbin]]. Essentially, it mangles the `chunk->next` pointer of each freed chunk using a heap address, forcing an attacker to acquire a heap leak first to effectively corrupt tcache/fastbin. It is performed via the [`PROTECT_PTR` macro](https://elixir.bootlin.com/glibc/glibc-2.41/source/malloc/malloc.c#L329), and the corresponding `REVEAL_PTR` macro just reverses safe linking (thus demangling/recovering the pointer).
```c
/* Safe-Linking:
   Use randomness from ASLR (mmap_base) to protect single-linked lists
   of Fast-Bins and TCache.  That is, mask the "next" pointers of the
   lists' chunks, and also perform allocation alignment checks on them.
   This mechanism reduces the risk of pointer hijacking, as was done with
   Safe-Unlinking in the double-linked lists of Small-Bins.
   It assumes a minimum page size of 4096 bytes (12 bits).  Systems with
   larger pages provide less entropy, although the pointer mangling
   still works.  */
#define PROTECT_PTR(pos, ptr) \
  ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)
```
In tcache, for instance, it is used [here](e->next = PROTECT_PTR (&e->next, tcache->entries[tc_idx]);) in `tcache_put` (adds chunk to `tcache`):
```c
e->next = PROTECT_PTR (&e->next, tcache->entries[tc_idx]);
```
Essentially, it mangles the true `chunk->next` pointer to the next chunk in the bin (`tcache->entries[tc_idx]` points to the head of this tcache bin) using the upper bits of the address of `e->next` (a heap address).
# Attack
## Prerequisites
- Heap leak (typically a mangled `chunk->next` pointer) %% #pwn/heap-leak %%
## Results
- Heap base address + ability to mangle/demangle pointers freely, i.e. control over `chunk->next`.
## Process
The idea is to leverage the fact that the mangling is only done using the upper bits of a heap address. In other words, this gets rid of the last 3 nibbles of the address, and thus the parameter `pos` is simply the bits determined by [[ASLR]]. Thus, once we have a heap leak, we can decrypt safe linking quite simply.
Here are two short snippets in Python that can be used for safe linking once a heap leak is acquired.
```python
def demangle(val: int) -> int:
    mask = 0xfff << 52
    while mask:
        v = val & mask
        val ^= (v >> 12)
        mask >>= 12
    return val

def mangle(heap_addr: int, val: int) -> int:
    return (heap_addr >> 12) ^ val
```
The below image from \[1\] also illustrates how only the upper ASLR bits are used for safe linking.
![[safe linking.png|500]]
### First tcache chunk
Notably, the first chunk in a tcache bin will have `chunk->next = 0`. Therefore, if you manage to leak the `chunk->next` pointer of this first chunk, what you'll get isn't really a mangled pointer, actually. Instead, it'll just be the upper 52 bits of ASLR. So, if leaking from the first chunk in a tcache bin, there's no need to decrypt anything: simply shift left by 12 bits to get the heap base (may need to subtract an offset depending on whether or not the chunk is in the first `0x1000` bytes of the heap).
# References
1. https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/