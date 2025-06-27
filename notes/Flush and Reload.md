---
tags:
  - pwn/technique
  - pwn/microarchitecture
  - pwn/microarchitecture/cache
---
# Attack
## Concept
The Flush & Reload attack targets the timing difference introduced by a cache. By flushing some memory location from the cache, and then later loading that memory, an attacker can identify whether or not a user has accessed that section of memory by measuring the how long it took the CPU to load the memory, i.e. distinguishing between a cache *hit* and a cache *miss*.
## Prerequisites
- The memory location `&a` must be **shared** between the victim and attacker
## Results
- Knowledge of whether or not the victim accessed the memory location `&a`
## Attack
1. The attacker *loads* the cache line of `&a` into the cache by accessing `&a`
2. The attacker **flushes** the cache line of `&a` from the cache
3. The attacker waits until the victim finishes executing some process. A typical situation may be that, if `secret = 1`, the victim will access `&a`.
4. The attacker now **reloads** the cache line of `&a` by attempting to access `&a` and timing the memory access.
	1. If the memory access is fast (*cache hit*), the attacker now knows the victim *did* access `&a` and thus `secret = 1`
	2. If the memory access is slow (*cache miss*), the attacker now knows the victim *did not* access `&a` and thus `secret = 0`
# References
- https://cass-kul.github.io/exercises/7-cache/#basic-cache-attack-flushreload