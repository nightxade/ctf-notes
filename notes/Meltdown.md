---
tags:
  - pwn/microarchitecture/cache
  - pwn/microarchitecture/transient-execution
---
# Description
Meltdown is a microarchitectural attack targeting a vulnerability in CPU hardware, especially Intel chips, via [[transient execution]]. It has been **mitigated** by [[KPTI]] in Linux, which was originally published as [[KAISER]], and similar, distinctly named variants in other operating systems like Windows.

TL;DR: Meltdown enables an adversary to arbitrarily extract memory from kernel addresses, and consequently other processes as well. The attacker abuses the architectural behavior of transient execution on Intel chips to transiently read memory and sends it through a [[covert channel]] using the CPU cache. Then, the attacker retrieves the secret information via a cache [[side channel]].
# Attack
## Fundamental Idea
For demonstration purposes, we assume the attacker is operating as a userspace attacker with code execution capabilities on the host system, and is attempting to read memory from kernel addresses. We will also assume the host system is using vulnerable Intel chips.
### Step 1: "Sending" Secrets via Transient Execution
Transient execution occurs when a CPU predictively (speculatively) runs instructions beyond the current instruction to minimize program runtime. Most commonly, this is a result of branch prediction. Consider [[Tomasulo's Algorithm]], for instance, applied to x86 instructions. The x86 instructions are decoded into $\mu$OPs, which are queued for execution across distinct execution units. The $\mu$OPs are executed as soon as the data necessary for their execution is available. However, if the prediction is incorrect, the results are never retired—that is, the results never change the actual program state. Critically, though, the results *can* affect the microarchitectural state of the CPU. In particular, transient memory accesses are typically cached. *This* is what Meltdown targets. Consider the following example code:
```asm
 ; rcx = kernel address, rbx = probe array
 xor rax, rax
 mov al, byte [rcx] 
 mov rbx, qword [rbx + rax]
```
This is the most fundamental idea of Meltdown.

First, the program transiently loads a kernel address. This is not a result of branch prediction, but rather, a result of *delayed permission checks*. The process's page table certainly marks this address as accessible only in supervisor mode; however, this check is not performed until later, after transient execution of these instructions has already completed. Thus, during the transient execution window, the $\mu$OPs for this instruction have already completed, just without retiring.

Then, the program transiently accesses an address in the probe array, based on the value loaded into `rax` from the kernel address `rcx`. Again, this result never retires. But, because of the microarchitectural behavior, this userspace address access *is cached*.

Note: this is actually just a [[race condition]] between the CPU attempting to retire the instruction loading the kernel address (and subsequently raising an exception) and the execution of the instruction accessing the probe array.
### Step 2: "Retrieving" Secrets from the Covert Channel
Pretending for a moment that our cache has a cache line size of just one byte, we can leverage an attack like [[Flush and Reload]] or [[Prime and Probe]] to subsequently retrieve the value of `rax`, successfully leaking data from otherwise inaccessible kernel memory.
## Optimizations and Considerations
### Prefetchers
Hardware prefetchers frequently load adjacent memory locations into the cache as well to increase performance. Because of this, we actually need to offset our probe array accesses by a whole page, i.e. 4 KB = 4096 bytes. That is,
```asm
 ; rcx = kernel address, rbx = probe array
 xor rax, rax
 mov al, byte [rcx] 
 shl rax, 0xc
 mov rbx, qword [rbx + rax]
```
### Noise Bias towards 0
Some CPUs, instead of stalling for a value during an out-of-order load operation, will forward a '0' value. This is just a result of the race condition inherent in out-of-order execution, and thus losing the race (which will happen occasionally) biases results towards 0. This bias becomes particularly apparent with an unoptimized Meltdown attack.

The fix is simple: just don't measure the '0' cache line. Rather, we can check if there is any cache hit on the other cache lines. If there is none, we can then assume that `rax` was '0'. To minimize the number of occurrences of this happening (since attacks like Flush and Reload can be runtime-expensive), we can also add on to our current code:
```asm
 ; rcx = kernel address, rbx = probe array
 xor rax, rax
 retry:
 mov al, byte [rcx] 
 shl rax, 0xc
 jz retry
 mov rbx, qword [rbx + rax]
```
In other words, retrying the address load until we receive a nonzero value. This maximizes the number of retries (of the same race condition on data forwarding) while not increasing the attack's latency (an exception will still be thrown once the CPU attempts to retire the first load instruction, which should take the same duration regardless).
### Single-bit transmission
As aforementioned, retrieving secrets from the covert channel via Flush and Reload or similar attacks can be fairly expensive with regards to runtime, with each measurement typically taking several hundred cycles. The transient execution portion is much more efficient. In the current implementation, we send a byte across the covert channel in each iteration. We can instead send a bit across the covert channel in each iteration:
```asm
 ; rcx = kernel address, rbx = probe array
 xor rax, rax
 retry:
 mov al, byte [rcx] 
 shr rax, 0x7
 shl rax, 0x13
 jz retry
 mov rbx, qword [rbx + rax]
```
In this way, we only need to perform a single Flush and Reload measurement on the '1' cache line. This provides another performance improvement.
### Exceptions
When the CPU attempts to retire the instruction accessing the kernel address, it will inevitably trigger an exception, as the page table marks the page containing the kernel address as requiring supervisor mode. This will typically terminate the program, which generates a lot of overhead. The paper suggested two methods of resolving this:
#### Exception Handling
The idea is simple. Either:
1. Fork a child process for the transient execution, and recover the secret in the parent process.
2. Add a signal handler for the exception.
Both methods will prevent the process from crashing. But, it does still introduce some overhead, as the exception will generate an interrupt that the kernel must catch before passing execution back to the userspace process.
#### Exception Suppression
One approach is to utilize **transactional memory** to treat memory accesses as a single atomic operation and quickly revert to a previous state if an exception occurs. without trapping into the kernel. Intel created a hardware implementation of this known as Intel Transactional Synchronization Extensions (**Intel TSX**).

Another approach is to use branch misprediction to the program's advantage. However, this can require a more detailed approach in "training" the branch predictor to mispredict accordingly.
### Direct-Physical Map
The [[direct physical map]] essentially maps the entirety of a machine's physical memory (RAM) into the kernel. This has the unintended effect of allowing Meltdown to effectively access the address spaces of any other process on the host machine (which can also be searched efficiently for a target process via the `init_task` structure, a linked list storing all processes). It also allows for Meltdown to be exploited from a container, since containerization solutions commonly share kernels and thus have their address spaces stored in the direct physical map.
### KASLR
[[KASLR]], kernel address space layout randomization, randomizes the kernel base offset. (At the time, [fine-grained KASLR](https://lwn.net/Articles/812438/) had yet to be introduced). However, because the direct physical map exists in the kernel, it suffices to probe the address space using steps equivalent to the target machine's physical RAM. Since KASLR's entropy is only 40 bits, a computer with 8 GB of RAM requires only 128 tests in the worst case. Once a leak is acquired, the attacker can easily retrieve the rest of the kernel memory.
# References
1. Lipp, Moritz, et al. "Meltdown." ([[meltdown.pdf]])