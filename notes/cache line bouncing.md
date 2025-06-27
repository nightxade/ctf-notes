---
tags:
  - pwn/microarchitecture
  - pwn/microarchitecture/cache
---
# Description
Cache line bouncing refers to a cache slowdown commonly produced by parallelized applications. It is best illustrated with an example:
Consider the following C code.
```c
#include <pthread.h>

struct shared_data_struct {
	int a;
	int b;
};

void t1_func(void* arg) {
	struct shared_data_struct *sd = (struct shared_data_struct *)arg;
	for (int i=0; i<100; i++) {
		sd->a++;
	}
}

void t2_func(void* arg) {
	struct shared_data_struct *sd = (struct shared_data_struct *)arg;
	for (int i=0; i<100; i++) {
		sd->b++;
	}
}

static struct shared_data_struct shared_data __cacheline_aligned__;

int main() {
	pthread_t t1;
	pthread_t t2;

	pthread_create(&t1, NULL, &t1_func, &shared)
	pthread_create(&t2, NULL, &t2_func, &shared)

	// pretend that t1 and t2 are joined here

	return 0;
}
```

Because `a` and `b` are in the same cache line, the following happens when each is written to:
- When Thread #1 writes to `sd->a`, this inevitably marks the cache line of `sd` *dirty* in Thread #2, despite the fact that this write does not change the behavior of Thread #2 (since it does not access `sd->b`. Thus, the cache for Thread #2 must actually *evict* its cache line for `sd` and retrieve `sd` from DRAM, leading to large increases in runtime despite no difference in behavior.
- The analogue happens for when Thread #2 writes to `sd->b`.
Essentially, the locality-based behavior of the cache actually leads to increased runtime. When two memory locations in the same cache line are independently read and written to by different threads/processes (they just need to have different caches), then this causes an unnecessary slowdown as the caches are forced to repeatedly evict and reload the cache line. This event is called **cache line bouncing**.
# References
- http://arighi.blogspot.com/2008/12/cacheline-bouncing.html