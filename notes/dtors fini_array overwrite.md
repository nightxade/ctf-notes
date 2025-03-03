---
tags:
  - pwn
  - pwn/technique
---
# Description
Overwriting the `.dtors` (old) / `.fini_array` (new) [[ELF#.finiarray (old .dtors)|section]], which is an array of pointers to functions that are called when the program exits regularly by returning from `main()`.
# Links
https://lwn.net/2000/1214/a/sec-dtors.php3
https://ctftime.org/writeup/20798