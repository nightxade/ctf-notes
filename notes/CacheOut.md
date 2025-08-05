---
tags:
  - pwn/microarchitecture/transient-execution
  - pwn/microarchitecture/cache
---
# Description
CacheOut is a [[transient execution]] microarchitectural attack that is able to leak data from microarchitectural buffers (**Microarchitectural Data Sampling, MDS**) during transit. Additionally, it is capable of leaking arbitrary data from the L1-D cache and control what to leak from the victim address space—which was a novelty upon its release
# Background
CacheOut is primarily concerned with the [[Line Fill Buffer]] (LFB), which is responsible for certain data transfers between the L1-D cache, the L2 cache, and the core. See the notes for LFBs for more details.

CacheOut is additionally reliant on Intel's Transactional Synchronization Extensions (TSX). Essentially, via the `xbegin` and `xend` TSX instructions, programs can denote sections of code as transactional and effectively execute these instructions atomically. However, this assumes a lack of concurrency conflicts across the transactional instructions. If there exists a conflict, the program is aborted, i.e. reverted to its initial state prior to the transaction, and then execution is continued. In other words, Intel TSX is another form of **transient execution**.

[[TSX Asynchronous Abort]] (TAA) is another transient execution attack that leaks data from the LFB. In short, it attempts to load data transactionally while an instruction flushing the memory address being accessed is in flight. This will cause a cache line conflict, inducing a transactional abort. However, the transient execution leaves a microarchitectural effect in the LFB, which can be leaked via cache attacks like [[Flush and Reload]] or [[Prime and Probe]]. This attack is extended in CacheOut in the form of [[#TAA-NG]] to allow reading entire cache lines, as TAA can only leak at most 8 bytes of every 64-byte cache line.
# Attack
## Attacking Victim Writes
In other words, leaking a victim's secret after they wrote to an address.

Here is the main idea:
```c
// victim:
// (1)
a = secret

// attacker:
// (2)
for (i = 0; i < 8; ++i) //evict secret from L1D cache
	*(evict_set + 4096 * i) = 0;

// (3)
TAA-NG(FRbuffer);

// (4)
for (i = 0; i < 256; ++i)
	if (flush_reload(FRbuffer + i * 4096))
		++results[i];
```
### Step 1: Victim Write
The victim writes the secret to the address `&a`. This is cached in the L1-D cache.
### Step 2: Eviction
First, the attacker finds the correct eviction set for the secret. The attacker then accesses this eviction set to evict the victim's secret from the L1-D cache. This actually transfers this data into the LFB, a previously [[#New Data Path|undocumented data path]].
### Step 3: TAA-NG
Then, using [[#TAA-NG]], the attacker leaks data from the LFB into the cache, i.e. the "send" step of this covert channel.
### Step 4: Flush and Reload
By using [[Flush and Reload]], the attacker receives the secret from the covert channel in the cache.
## Attacking Victim Reads
That is, leaking a victim's secret after they read the secret from an address.

Here is the main idea:
```c
// attacker:
// (1)
for (i = 0; i < 8; ++i) //evict secret from L1D cache
	*(evict_set + 4096 * i) = 0;

// victim:
// (2)
if (secret) { // this loads secret into the L1-D cache
	do_something();
}

// (3)
TAA-NG(FRbuffer);

// (4)
for (i = 0; i < 256; ++i)
	if (flush_reload(FRbuffer + i * 4096))
		++results[i];
```
### Step 1: Eviction
This is the same as in the write attack.
### Step 2: Victim Read
The victim uses the secret value in some way, effectively reading it and thus loading it into the L1-D cache.
### Step 3: TAA-NG
Same as write attack.
### Step 4: Flush and Reload
Same as write attack.
## TAA-NG

## Key Results
### Control Over Desired Leakage
By using eviction sets, an attacker can precisely control the desired cache line to leak from the victim's address space.
### Full Cache Line Leakage
As aforementioned, [[#TAA-NG]] allows an attacker to leak qwords from arbitrary offsets in a cache line of the LFB, rather than just 8 bytes.
### Arbitrary L1-D Leakage
Data appears to remain present in the L1-D cache for millions of cycles. By evicting from the L1-D, rather than simply sampling from the LFB and hoping the target data is in-flight, an attacker can precisely target any victim data in the L1-D cache.
## Other Notes
### New Data Path

# Mitigations
Intel TSX is no longer supported on newer Intel chips (since 2021, from *Skylake* beyond), which CacheOut relies on for its exploit.
# References
1. Van Schaik, Stephan, et al. "CacheOut: Leaking data on Intel CPUs via cache evictions." 2021 IEEE Symposium on Security and Privacy (SP). IEEE, 2021. ([[cacheout.pdf]])