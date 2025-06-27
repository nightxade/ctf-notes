---
tags:
  - pwn/technique
  - pwn/kernel
  - pwn/priv-esc
  - pwn/patch/v6-14-rc1
---
# Description
`modprobe_path` is a technique used to gain local privilege escalation when exploiting the kernel. It leverages the behavior of the Linux kernel when loading a module and the `modprobe` program, an executable in userspace located at `/usr/bin/modprobe`, to execute a user-controlled program as root.
# Attack
## Prerequisites
- Arbitrary write
# References
- https://sam4k.com/like-techniques-modprobe_path/