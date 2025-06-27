---
tags:
  - pwn/code
---
# Description
> [!todo]

# Uses
- Can cause [[malloc_consolidate()]] to be called with a large enough buffer.
- Can trigger [[heap hook overwrite|heap hooks]] to be called with a large enough buffer, specifically `__malloc_hook` and `__free_hook`.