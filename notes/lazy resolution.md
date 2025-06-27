---
tags:
  - bin/elf
---
# Algorithm
1. The process jumps to the lazy stub in [[PLT]] $\to$ jumps to address in [[GOT]] $\to$ jumps to `plt[0]` $\to$ calls `_dl_runtime_resolve`
	GOT code:
	```asm
	push n           ; relocation table index (symbol index)
	jmp  plt[0]      ; jumps into the dynamic resolver
	```
	`plt[0]` contains a trampoline that redirects to the **dynamic resolver**:
	```asm
	push ModuleID    ; address of the current binary's link_map, contains addresses of sections
	jmp _dl_runtime_resolve
	```

2. Resolver uses the symbol index to index into [[ELF#.rela.plt|.rela.plt]], extracting the relocation entry, which contains:
	- GOT address to patch
	- Index of this function in [[ELF#.dynsym|.dynsym]] (symbol table)
3. Using `st_name` (index of symbol in string table) from the `.dynsym` entry, the symbol name is retrieved from [[ELF#.dynstr|.dynstr]] (string table)
4. Symbol name is used to find a matching symbol from the loaded shared libraries (.so files)
5. Using `st_value`(virtual address offset of target function, i.e. offset from base address) from the `.dynsym` entry, final symbol address is computed and subsequently written into the GOT address.
6. Now jumps to the real function address via the GOT.

The actual chain of function calls is:
```c
_dl_runtime_resolve
         └───► _dl_fixup
                    └───►_dl_lookup_symbol_x
                               └───► do_lookup_x
```
[source](https://4xura.com/pwn/heap/house-of-muney/#toc-head-10)

# Links
- [*Very* in-depth explanation of lazy linking](https://4xura.com/pwn/heap/house-of-muney/#toc-head-44)
