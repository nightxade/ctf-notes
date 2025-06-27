---
tags:
  - pwn/technique
  - pwn/kernel
  - pwn/priv-esc
  - pwn/patch/v6-14-rc1
---
# Description
`modprobe_path` is a technique used to gain local privilege escalation when exploiting the kernel. It leverages the behavior of the Linux kernel when loading a module and the `modprobe` program, an executable in userspace located at `/usr/bin/modprobe`, to execute a user-controlled program as root, by overwriting `modprobe_path`.
# Attack
## Prerequisites
- Arbitrary write primitive
- Address of `modprobe_path` (leak if [[KASLR]] is enabled)
## Result
- Local privilege escalation (**LPE**)
## Analysis
We will first consider the result of a userspace program calling [execve](https://man7.org/linux/man-pages/man2/execve.2.html). (Linux kernele v5.18.5)
### Calling `execve`
`execve` eventually uses an `execve` [[syscall]] to throw an interrupt and transfer control flow to the kernel
```c
SYSCALL_DEFINE3(
	execve,
	const char __user * filename,
	const char __user *const __user * argv,
	const char __user *const __user * envp)
{
	return do_execve(getname(filename), argv, envp);
}
```
Several function calls later, we arrive at the kernel function `search_binary_handler()`. Here's the backtrace of functions so far:
```c
search_binary_handler(struct linux_binprm *bprm)  // current
exec_binrpm(...)
bprm_execve(...)
do_execveat_common(...)
do_execve(...)
SYSCALL_DEFINE3(execve, ...)
syscall execve  // userspace syscall
```

# References
- https://sam4k.com/like-techniques-modprobe_path/