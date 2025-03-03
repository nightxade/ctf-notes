---
tags:
  - pwn
  - rev
  - bin/elf
---
# Description
The standard binary format for Unix and Unix-like systems.
# Sections
## .text
The section where the main code of the program is.
## .init
This section holds executable instructions that contribute to the process initialization code. That is, when a program starts to run the system arranges to execute the code in this section before the main program entry point (called _main_ in C programs)... If a function is placed in the **.init** section, the system will execute it before the _main_ function. [1]
### Info
- It contains only a function call to  `__do_global_ctors_aux`, which goes through [[#.initarray|.init_array]] from the head and calls each destructor function on the list. [1,2]
## .init_array (old: .ctors)
Contains an array of pointers to functions to use as constructors (each of these functions is called in turn when the binary is initialized). In `gcc` , you can mark functions in your C source files as constructors by decorating them with `__attribute__((constructor)`. By default, there is an entry in `.init_array` for executing `frame_dummy`. [2]
## .fini
This section holds executable instructions that contribute to the process termination code. That is, when a program exits normally, the system arranges to execute the code in this section.... The functions placed in the **.fini** section will be executed by the system after the _main_ function returns. This feature is utilized by compilers to implement global constructors and destructors in C++. [1]
### Info
- It contains only a function call to `__do_global_dtors_aux`, which goes through [[#.finiarray|.fini_array]] from the tail and calls each constructor function on the list. [1,2]
## .fini_array (old: .dtors)
Contains an array of pointers to functions to use as destructors. [2]
## .bss
It contains data that **is not** initialized at the beginning of the program, i.e. filled with null bytes, and is **writeable**.
## .data
It contains data that **is** initialized at the beginning of the program and is **writeable**.
## .rodata
It contains data that **is** initialized at the beginning of the program and is **read-only**. For example, hard-coded strings.
## .plt
[[PLT|Procedure Linkage Table]].
## .got.plt
[[GOT|Global Offset Table]].
## .dynamic
> [!todo]
# References
1. [ELF: From The Programmer's Perspective](https://ftp.math.utah.edu/u/ma/hohn/linux/misc/elf/elf.html) (somewhat old)
2. [ELF Format Cheatsheet](https://gist.github.com/x0nu11byt3/bcb35c3de461e5fb66173071a2379779)
