---
tags:
  - pwn/heap
  - pwn/code
---
# Description
`malloc_state` is a struct for the [[main arena]]. It is defined as the following in *glibc 2.41*:
```c
typedef struct malloc_chunk* mchunkptr;

struct malloc_state
{
  /* Serialize access.  */
  __libc_lock_define (, mutex);

  /* Flags (formerly in max_fast).  */
  int flags;

  /* Set if the fastbin chunks contain recently inserted free blocks.  */
  /* Note this is a bool but not all targets support atomics on booleans.  */
  int have_fastchunks;

  /* Fastbins */
  mfastbinptr fastbinsY[NFASTBINS];

  /* Base of the topmost chunk -- not otherwise kept in a bin */
  mchunkptr top;

  /* The remainder from the most recent split of a small request */
  mchunkptr last_remainder;

  /* Normal bins packed as described above */
  mchunkptr bins[NBINS * 2 - 2];

  /* Bitmap of bins */
  unsigned int binmap[BINMAPSIZE];

  /* Linked list */
  struct malloc_state *next;

  /* Linked list for free arenas.  Access to this field is serialized
     by free_list_lock in arena.c.  */
  struct malloc_state *next_free;

  /* Number of threads attached to this arena.  0 if the arena is on
     the free list.  Access to this field is serialized by
     free_list_lock in arena.c.  */
  INTERNAL_SIZE_T attached_threads;

  /* Memory allocated from the system in this arena.  */
  INTERNAL_SIZE_T system_mem;
  INTERNAL_SIZE_T max_system_mem;
};
```
[source](https://elixir.bootlin.com/glibc/glibc-2.41/source/malloc/malloc.c#L1814)
## mutex
Thread lock for multithreaded access to one arena.
## flags
> [!todo]
## fastbinsY
Array that stores the addresses of the first chunk in each [[bins#fastbin|fastbin]].
## top
[[top chunk]]
## last_remainder
[[last remainder chunk]]
## bins
bin\[0\] = N/A
bin\[1\] = [[bins#unsorted bin|unsorted bin]]
bin\[2:64\] = [[bins#small bin|small bin]]
bin\[64:127\] = [[bins#large bin|large bin]]
[source](https://azeria-labs.com/heap-exploitation-part-2-glibc-heap-free-bins/)

![[malloc_state_bins.png|750]]
## binmap
> [!todo]
## next
Pointer to next arena (forming a linked list of the process's arenas).