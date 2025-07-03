---
tags:
  - pwn/technique
  - pwn/kernel
  - pwn/priv-esc
  - pwn/patch/v6-14-rc1
---
# Description
`modprobe_path` is a technique used to gain local privilege escalation when exploiting the kernel. It leverages the behavior of the Linux kernel when loading a module and the `modprobe` program, an executable in userspace located at `/usr/bin/modprobe`, to execute a user-controlled program as root, by overwriting `modprobe_path`. It was [patched](https://web.git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=fa1bdca98d74472dcdb79cb948b54f63b5886c04) in the Linux kernel v6.14-rc1. There is a [newer technique](https://theori.io/blog/reviving-the-modprobe-path-technique-overcoming-search-binary-handler-patch) post-patch to exploit `modprobe_path`, though.
# Attack (pre v6.14-rc1)
## Prerequisites
- Arbitrary write primitive
- Address of `modprobe_path` (leak if [[KASLR]] is enabled)
## Result
- Local privilege escalation (**LPE**)
## Analysis
We will consider the process of a userspace program calling [execve](https://man7.org/linux/man-pages/man2/execve.2.html). (Linux kernel v5.18.5). `execve()` eventually uses an `execve` [[syscall]] to throw an interrupt and transfer control flow to the kernel
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
Several function calls later, we arrive at the kernel function [`search_binary_handler()`](https://elixir.bootlin.com/linux/v5.18.5/source/fs/exec.c#L1702). Here's the backtrace of functions so far:
```c
search_binary_handler(struct linux_binprm *bprm)  // current
exec_binrpm(...)
bprm_execve(...)
do_execveat_common(...)
do_execve(...)
SYSCALL_DEFINE3(execve, ...)
syscall execve  // userspace syscall
```
`search_binary_handler(struct linux_binrpm *bprm)` essentially looks for a binary format handler (`struct linux_binfmt`) in the doubly-linked list [`formats`](https://elixir.bootlin.com/linux/v5.18.5/source/fs/exec.c#L82). Note that `linux_binrpm` represents a binary parameter structure that "holds arguments that are used when loading binaries." ([here](https://elixir.bootlin.com/linux/v5.18.5/source/include/linux/binfmts.h#L18)). In this case, the binary being loaded is the file passed in the `filename` parameter for the `execve` syscall.
```c
/*
 * cycle the list of binary formats handler, until one recognizes the image
 */
static int search_binary_handler(struct linux_binrpm *bprm) {
	...
	read_lock(&binfmt_lock);
	list_for_each_entry(fmt, &formats, lh) {
		if (!try_module_get(fmt->module))
			continue;
		read_unlock(&binfmt_lock);
		
		retval = fmt->load_binary(bprm);
		
		read_lock(&binfmt_lock);
		put_binfmt(fmt);
		if (bprm->point_of_no_return || (retval != -ENOEXEC)) {
			read_unlock(&binfmt_lock);
			return retval;
		}
	}
	...
}
```
Essentially, `list_for_each_entry(fmt, &formats, lh)` iterates through `formats`, and tests if the `load_binary(bprm)` call (different implementations between formats) is valid for our `bprm`. That is, this will check if `load_binary` can process `bprm->buf`, which contains the first [<abbr title="256">BINPRM_BUF_SIZE</abbr>](https://elixir.bootlin.com/linux/v5.18.5/source/include/uapi/linux/binfmts.h#L19) bytes of our binary ([here](https://elixir.bootlin.com/linux/v5.18.5/source/include/linux/binfmts.h#L67)).
However, if no binary format handler works for our `bprm`, we hit this block later in the function:
```c
#define printable(c) (((c)=='\t') || ((c)=='\n') || (0x20<=(c) && (c)<=0x7e))
/*
 * cycle the list of binary formats handler, until one recognizes the image
 */
static int search_binary_handler(struct linux_binrpm *bprm) {
	...
	if (need_retry) {
		if (printable(bprm->buf[0]) && printable(bprm->buf[1]) && printable(bprm->buf[2]) && printable(bprm->buf[3]))
			return retval;
		if (request_module("binfmt-%04x", *(ushort *)(bprm->buf + 2)) < 0)
			return retval;
		need_retry = false;
		goto retry;
	}
	...
}
```
Most notably, if at least one of the first four bytes of  `brpm->buf` (our binary) is non-printable, then the kernel will, instead of returning, attempt to call `request_module("binfmt-%04x", *(ushort *)(bprm->buf + 2)) < 0)`. `request_module` is a [macro](https://elixir.bootlin.com/linux/v5.18.5/source/include/linux/kmod.h#L25) for [`__request_module`](https://elixir.bootlin.com/linux/v5.18.5/source/kernel/kmod.c#L124)) such that it will attempt to load a kernel module and wait for the operation to complete. Specifically, it tries to "load a module using the user mode module loader." ;)
```c
#define request_module(mod...) __request_module(true, mod)

/**
 * __request_module - try to load a kernel module
 * @wait: wait (or not) for the operation to complete
 * @fmt: printf style format string for the name of the module
 * @...: arguments as specified in the format string
 * *
 * Load a module using the user mode module loader. The function returns zero on success or a negative errno code or positive exit code from "modprobe" on failure. Note that a successful module load does not mean the module did not then unload and exit on an error of its own. Callers must check that the service they requested is now available not blindly invoke it.
 * If module auto-loading support is disabled then this function simply returns -ENOENT.
 */
 int __request_module(bool wait, const char *fmt, ...)
 {
	if (!modprobe_path[0])
		 return -ENOENT;
	...
	// some checks about module name length, concurrency
	...
	ret = call_modprobe(module_name, wait ? UMH_WAIT_PROC : UMH_WAIT_EXEC);
	...
	return ret
 }
```
Here, the kernel first checks if [`modprobe_path`](https://elixir.bootlin.com/linux/v5.18.5/source/include/linux/ kmod.h#L20) is defined or not. As stated in the function description, this is undefined when "module auto-loading support is disabled." Typically, `modprobe_path` is set to `/usr/bin/modprobe`. After some other miscellaneous checks, it calls [`call_modprobe(module_name, wait ? UMH_WAIT_PROC : UMH_WAIT_EXEC)`](https://elixir.bootlin.com/linux/v5.18.5/source/kernel/kmod.c#L69). Here's the whole function:
```c
static int call_modprobe(char *module_name, int wait)
{
	struct subprocess_info *info;
	static char *envp[] = {
		"HOME=/",
		"TERM=linux",
		"PATH=/sbin:/usr/sbin:/bin:/usr/bin",
		NULL
	};

	char **argv = kmalloc(sizeof(char *[5]), GFP_KERNEL);
	if (!argv)
		goto out;

	module_name = kstrdup(module_name, GFP_KERNEL);
	if (!module_name)
		goto free_argv;

	argv[0] = modprobe_path;
	argv[1] = "-q";
	argv[2] = "--";
	argv[3] = module_name;	/* check free_modprobe_argv() */
	argv[4] = NULL;

	info = call_usermodehelper_setup(modprobe_path, argv, envp, GFP_KERNEL,
					 NULL, free_modprobe_argv, NULL);
	if (!info)
		goto free_module_name;

	return call_usermodehelper_exec(info, wait | UMH_KILLABLE);

free_module_name:
	kfree(module_name);
free_argv:
	kfree(argv);
out:
	return -ENOMEM;
}
```
After allocating space for `argv` and duplicating `module_name` to a new allocation, we see something very interesting: a command being constructed in `argv`:
```c
	argv[0] = modprobe_path;
	argv[1] = "-q";
	argv[2] = "--";
	argv[3] = module_name;	/* check free_modprobe_argv() */
	argv[4] = NULL;
```
In other words, it's creating the following command:
```bash
$ /usr/bin/modprobe -q -- binfmt-b0bacafe
```
Where `b0 ba ca fe` would be the first 4 bytes of our binary in hex.

Critically, the call to [`call_usermodehelper_setup()`](https://elixir.bootlin.com/linux/v5.18.5/source/kernel/umh.c#L358) and subsequently [`call_usermodehelper_exec()`](https://elixir.bootlin.com/linux/v5.18.5/source/kernel/umh.c#L404), according to the GLIBC comments:

> Runs a user-space application. The application is started asynchronously if wait is not set, and runs as a child of system workqueues.
> (ie. it runs with **full root capabilities** and optimized affinity).

Yup. This will run the command as **root**.

What does this tell us? Well, this means that if an unprivileged user can gain control of an *arbitrary write primitive* and knows where `modprobe_path` is in memory, they can overwrite `modprobe_path` with a path to their own, user-controlled binary. Then, by attempting to call `execve()` on a binary whose first 4 bytes are not handled by any known binary handler (e.g. `b0 ba ca fe`), the kernel will execute the user-controlled binary with root privileges. Yay!
## Examples
- [CVE-2022-27666](https://etenal.me/archives/1825) (Etenal7)
- [CVE-2022-0185](https://www.willsroot.io/2022/01/cve-2022-0185.html) (Crusaders of Rust)
- [Blog](https://lkmidas.github.io/posts/20210223-linux-kernel-pwn-modprobe/) (\_lkmidas)
## Mitigations
### CONFIG_STATIC_USERMODEHELPER
[`CONFIG_STATIC_USERMODEHELPER`](https://cateee.net/lkddb/web-lkddb/STATIC_USERMODEHELPER.html) was introduced in 4.11, and makes `modprobe_path` read-only, thereby preventing arbitrary privileged execution.
### search_binary_handler() patch
This [patch](https://web.git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=fa1bdca98d74472dcdb79cb948b54f63b5886c04) that released with v6.14-rc1 cleaned up the deprecated functionality in `search_binary_handler()`. Specifically, it removed the call to `request_module()`, thereby preventing `call_modprobe` from being reached through the execution path of `execve() -> search_binary_handler()`.
```diff
@@ -1760,17 +1756,7 @@ static int search_binary_handler(struct linux_binprm *bprm)
        }
        read_unlock(&binfmt_lock);
        // [4]
-       if (need_retry) {
-               if (printable(bprm->buf[0]) && printable(bprm->buf[1]) &&
-                   printable(bprm->buf[2]) && printable(bprm->buf[3]))
-                       return retval;
-               if (request_module("binfmt-%04x", *(ushort *)(bprm->buf + 2)) < 0)
-                       return retval;
-               need_retry = false;
-               goto retry;
-       }
-
-       return retval;
+       return -ENOEXEC;
 }

 /* binfmt handlers will call back into begin_new_exec() on success. */
```
# Attack (post v6.14-rc1)
> [!TODO]
# References
- [pre v6.14-rc1](https://sam4k.com/like-techniques-modprobe_path/) (a lot of paraphrasing from here, basically)
- [post v6.14-rc1](https://theori.io/blog/reviving-the-modprobe-path-technique-overcoming-search-binary-handler-patch) 