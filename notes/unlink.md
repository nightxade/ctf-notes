---
tags:
  - pwn/heap
  - pwn/code
---
# Description
Unlinking is the process of removing a chunk from a doubly-linked bin, i.e. [[bins#small bin|small bin]], [[bins#large bin|large bin]], and [[bins#unsorted bin|unsorted bin]]. It is carried out in the [`unlink_chunk`](https://elixir.bootlin.com/glibc/glibc-2.41/source/malloc/malloc.c#L1610) function:
```c
/* Take a chunk off a bin list.  */
static void
unlink_chunk (mstate av, mchunkptr p)
{
  if (chunksize (p) != prev_size (next_chunk (p)))
    malloc_printerr ("corrupted size vs. prev_size");

  mchunkptr fd = p->fd;
  mchunkptr bk = p->bk;

  if (__builtin_expect (fd->bk != p || bk->fd != p, 0))
    malloc_printerr ("corrupted double-linked list");

  fd->bk = bk;
  bk->fd = fd;
  if (!in_smallbin_range (chunksize_nomask (p)) && p->fd_nextsize != NULL)
    {
      if (p->fd_nextsize->bk_nextsize != p
		  || p->bk_nextsize->fd_nextsize != p)
		malloc_printerr ("corrupted double-linked list (not small)");

      if (fd->fd_nextsize == NULL)
		{
		  if (p->fd_nextsize == p)
		    fd->fd_nextsize = fd->bk_nextsize = fd;
		  else
		    {
		      fd->fd_nextsize = p->fd_nextsize;
		      fd->bk_nextsize = p->bk_nextsize;
		      p->fd_nextsize->bk_nextsize = fd;
		      p->bk_nextsize->fd_nextsize = fd;
		    }
		}
	  else
		{
		  p->fd_nextsize->bk_nextsize = p->bk_nextsize;
		  p->bk_nextsize->fd_nextsize = p->fd_nextsize;
		}
    }
}
```
## Process
1. If `p->size != (p + p->size)->prev_size`, error "corrupted size vs. prev size" (checks prev size of next chunk that is adjacent to itself in memory).
2. If `p->fd->bk != p || p->bk->fd != p`, error "corrupted double-linked list" (forward/backward pointers are corrupted)
3. Update pointers of `p->fd->bk = p->bk` and `p->bk->fd = fd`, essentially removing the current chunk from the linked list.
4. If small bin sized, return. If large bin sized, continue.
5. If `p->fd_nextsize->bk_nextsize != p || p->bk_nextsize->fd_nextsize != p`, error "corrupted double-linked list (not small)" (forward/backward pointers are corrupted for the *sorted-by-size* doubly-linked list).
6. If `p->fd->fd_nextsize == NULL`
   If true, the next chunk in the regular doubly-linked list, `p->fd`, is of the same size. This also means the current chunk is the "head" of the doubly-linked list for its size, i.e. it is the first chunk of its size in this large bin. If this sounds confusing, read through the **!!!** in [[bins#large bin|this section]].
	1. If `p->fd_nextsize == p` (the current chunk size is the *only size* currently in this large bin, and the chunk being unlinked is the head of the large bin)
		1. Create a circular link for the sorted-by-size linked list with the next chunk (which will become the head of the large bin)
	2. Else:
		1. Set forward/backward pointers for the sorted-by-size linked list of the next chunk (which, again, is of the same size) to the current chunk's
		   ```c
		      fd->fd_nextsize = p->fd_nextsize;
		      fd->bk_nextsize = p->bk_nextsize;
		   ```
		2. Do pointer updates for the sorted-by-size linked list by
		   ```c
		      p->fd_nextsize->bk_nextsize = fd;
		      p->bk_nextsize->fd_nextsize = fd;
			```
		3. This essentially sets `fd` as the new "head" of the doubly-linked list for its size.
7. Else:
	1. Do normal pointer updates as in step 3, removing the current chunk from the sorted-by-size linked list.
# Attacks
- [[unsafe unlink]]