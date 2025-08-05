---
tags:
  - pwn/microarchitecture/cache
---
# Description
The Line Fill Buffer (LFB) is an intermediary between caches, most commonly the L1-D and L2 caches. It enables non-blocking cache operations by holding data fetched from lower level caches upon a cache miss. For instance, a cache miss in the L1-D cache will result in the LFB using one of its lines to store the retrieved data from the L2 cache, which it will subsequently forward to the CPU. This allows for the L1-D cache to continue serving operations while it is retrieving data from lower cache levels.