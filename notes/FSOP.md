---
tags:
  - pwn
  - pwn/technique
  - pwn/file-structs
---
# Description
Using the `chain` and `vtable` attributes of an `_IO_FILE` struct to write a "[[ROP]] chain" by chaining file structs. It is typically triggered by a call to `exit()`, which cleans up all open file descriptors.
> [!todo]
# Notes
```py  
# Author: Axura  
# URL: https://4xura.com/pwn/pwn-heap-exploitation-house-of-emma/  
# Source: Axura's Blog  

# how exit() triggers _IO_OVERFLOW
exit
  └───► fcloseall
		    └───► _IO_cleanup
					    └───►_IO_flush_all_lockp
										└───►_IO_OVERFLOW
```
# Links
https://ctf-wiki.mahaloz.re/pwn/linux/io_file/fsop/
https://4xura.com/pwn/pwn-heap-exploitation-house-of-emma/