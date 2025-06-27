---
tags:
  - pwn/technique
  - pwn/microarchitecture
---
# Attack
## Concept
Same concept as [[Flush and Reload]], except without the need for shared memory. Instead, the attacker leverages cache organization techniques (e.g. direct-mapped or set-associative cache) to gain knowledge of a user's access to a certain memory address. Also, it's helpful to think of Prime and Probe as basically the *reverse* of Flush and Reload.
## Prerequisites
- Known memory address `&atk`  (in attacker memory) that maps to the *same cache line* as the target address `&a` (in victim memory)
## Results
- Knowledge of whether or not the victim has accessed `&a`
## Process
1. The attacker *evicts* the cache line of `&a` by accessing `&atk` (i.e., the cache line of `&atk` replaces that of `&a`). This **primes** the cache, and is known as [[cache line bouncing]].
2. The attacker waits until the victim finishes executing some process. A typical situation may be that, if `secret = 1`, the victim will access `&a`.
3. The attacker now **probes** the cache by attempting to *load* the cache line of `&atk` and timing the memory access
	1. If the memory access is slow (*cache miss*), the attacker now knows the victim *did* access `&a` (as the victim's memory access would evict the cache line of `&atk`, forcing this probing access to retrieve `&atk` from DRAM) and thus `secret = 0`
	2. If the memory access is fast (*cache hit*), the attacker now knows the victim *did not* access `&a` and thus `secret = 1`
# References
- https://cass-kul.github.io/exercises/7-cache/#more-advanced-cache-attacks-primeprobe