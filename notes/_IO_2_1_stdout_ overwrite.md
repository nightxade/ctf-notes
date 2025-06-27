---
tags:
  - pwn/technique
  - pwn/file-structs
---
# Description
Overwriting the standard file descriptor of `_IO_2_1_stdout_` allows the attacker to gain an **arbitrary read**.
# Notes
- `_IO_2_1_stdout_` is located in the anon section after [[LIBC]]
- `fp.read_base`, `fp.read_ptr`, etc. are all set to the same value (except `fp.buf_end`)
### Requirements
- I/O operation (some function that writes to stdout, i.e. `puts`, guarantees this struct is used)
- `fp.write_base` > `fp.write_ptr`
- Either
    - `fp.flags & IO_APPENDING` is true (`IO_APPENDING = 0x1000`)
    - `fp.read_end == fp.write_base`
### Call Process (Ex: `puts()`)
1. `_IO_puts` [link](https://codebrowser.dev/glibc/glibc/libio/ioputs.c.html)
2. `_IO_sputn(stdout, str, len)` [link](https://codebrowser.dev/glibc/glibc/libio/libioP.h.html#380) $\implies$ `_IO_file_jumps[xsputn]` [link](https://codebrowser.dev/glibc/glibc/libio/vtables.c.html#149) $\implies$ `_IO_file_xsputn` [link](https://codebrowser.dev/glibc/glibc/libio/fileops.c.html#1431) $\implies$ `_IO_new_file_xsputn` [link](https://codebrowser.dev/glibc/glibc/libio/fileops.c.html#_IO_new_file_xsputn) 
3. `_IO_OVERFLOW(f, EOF)` [link](https://codebrowser.dev/glibc/glibc/libio/libioP.h.html#147) $\implies$ `_IO_file_jumps[overflow]` [link](https://codebrowser.dev/glibc/glibc/libio/vtables.c.html#145) $\implies$ `_IO_file_overflow` [link](https://codebrowser.dev/glibc/glibc/libio/fileops.c.html#1427) $\implies$ `_IO_new_file_overflow` [link](https://codebrowser.dev/glibc/glibc/libio/fileops.c.html#_IO_new_file_overflow)
4. `_IO_do_write(f, f->_IO_write_base, f->_IO_write_ptr - f->_IO_write_base)` [link](https://codebrowser.dev/glibc/glibc/libio/fileops.c.html#_IO_do_write) $\implies$ `_IO_new_do_write` [link](https://codebrowser.dev/glibc/glibc/libio/fileops.c.html#_IO_new_do_write)
	1. Requires `f->_IO_write_ptr - f->_IO_write_base != 0`
5. `new_do_write(fp, data, to_do)` [link](https://codebrowser.dev/glibc/glibc/libio/fileops.c.html#new_do_write)
	1. Requires either
	   `fp->_flags & _IO_IS_APPENDING` [link](https://codebrowser.dev/glibc/glibc/libio/fileops.c.html#434)
	   `fp->_IO_read_end == fp->_IO_write_base` [link](https://codebrowser.dev/glibc/glibc/libio/fileops.c.html#441) (otherwise `_IO_SYSSEEK`, i.e. `lseek`, is called with invalid args $\implies$ exits)
6. `_IO_SYSWRITE(fp, data, to_do)` [link](https://codebrowser.dev/glibc/glibc/libio/fileops.c.html#449) (win!)
### Results
- Leaks `memory[fp.write_base : fp.write_ptr]`
- When having limited control for overwriting `fp` attributes:
    - $stack: `libc.sym.environ`, located at end of anon section after libc
    - $libc: libc addresses in `fp`
    - $elf: elf addresses before `fp`
# Challenges
- PwnMe Quals CTF 2025 / pwn / einstein