---
tags:
  - pwn/technique
---
# Format String Tutorial  

## Vulnerability  

Whenever a call to printf is done like so:  

```c
printf(user_input);
```

Malicious printf format strings can print data located on the stack.  

A normal call to printf looks like this:  

```c
int num = 243;
printf("%d", num);
```

However, if the vulnerable call to printf is allowed, stack data can get printed if the user inputs something malicious. The following code example, lacking any arguments for the format string "%x", will instead print the next data\* on the stack.

> \* For lack of a better word, I will refer to each quadword on the stack as "data." Essentially, the "next data" is just the 8 bytes of data at an offset of `+0x8`.

```c
char user_input[] = "%x";
printf(user_input);
```

Try it yourself in your own local machine to see what happens :)  

## Important Format Specifiers + Modifiers  

This is a list of the useful format specifiers for pwn, to my knowledge:  

- `%x` or `%p` allows you to print the hex version of data on the stack. If "0x401450" is the next data on the stack, `printf("%x")` will print out `401450`.  
- `%n` allows you to write to any address on the stack! A detailed explanation on this is in the [[#Arbitrary Writes]] section.  
- `%s` allows you to read the data stored at an address on the stack. If "0x401450" is the next data on the stack, `printf("%s")` will print out the data stored at address 0x401450. Importantly, however, one should note that printf does not output null bytes. Therefore, if the data stored at 0x401450 contains null bytes, everything after the null bytes will not be printed!  
- `%c` allows you to read a single character off the stack.  

Now, there's some explanation needed for the various different specifiers that modify another specifier:  

- `$` is probably the most important. It allows you to access any data on the stack, not just the next data. For example, `printf("%4$x")` will print out the 4th nextmost data on the stack. Note that it always follows the format of `%[offset]$[format specifier]`. 
- `l`, `h`, and `hh` allow you to modify the size of the data you are reading or writing. They stand for 8, 2, and 1 bytes respectively. The default size (no size specifier) is 4 bytes. The format specifier always follows after the size specifier. For example, `printf("%4$lx")` will print the 8 bytes located at offset 4. You should note that `printf("%4$lx")` and `printf("%4$x")` actually refer to the same data on the stack!! Only, one of them will print all 8 bytes of the data, and one will print only the first 4. (Note that I am assuming we are working with x86_64 architecture. I believe `l` actually changes depending on the architecture, printing 8 bytes for x64 and 4 bytes for x32).  
- `*` is a bit of an interesting one. It's called a precision specifier, and it's honestly easier to explain this one with an example. It's intended usage is to pad numbers. For example, `printf("%*x", 8, 0x40)` would print out `      40`. Basically, it would set the output width to exactly 8. (This example had 6 spaces and 2 digits). Note that you can also specify the exact argument or data offset on the stack that you want to use for the precision specifier with something like this: `printf("%*4x")`. This will use the 4th nextmost data on the stack as the precision specifier. You'll see why this specifier is useful later on in the [[#Arbitrary Writes]] section.

#### Before you move on...  

Play around with these format specifiers and modifiers! Seriously, it's always a good idea to try and understand all these different format specifiers and modifiers before you move on. Write some simple printf statements in a C program, hop in to GDB, set some breakpoints, and make sure you know what each format string/specifier does. You can even take a look at the [printf man page](https://man7.org/linux/man-pages/man3/printf.3.html) to look through all the different format specifiers. Or just ask ChatGPT :)

From now on, we're going to see how we can abuse a program vulnerable to format string exploits. Let's use x86_64 architecture, and, WLOG, let's call it `vuln`:  

```c
#include <unistd.h>
#include <stdio.h>

int main() {

    char buf[256];
    read(0, buf, 256);
    printf(buf)

    return 0;
}
```

## Stack Reading  

If you understand all the format specifiers now, this should be pretty easy.  

To print out the next X data on the stack, it's easy enough to just send several `%lx`.  

Typically, I'll just send something like `"%lx|"*40`. This will print out the next `0x40 * 0x8 = 0x200` bytes on the stack. Note that the "|" is not actually necessary, but it's much harder to read and interpret the output you receive without the "|".

What about reading a specific offset on the stack?  

This is still pretty easy. We can make use of the "\$" specifier. For example, to read the 10th nextmost data on the stack, we can send `"%10$lx"`.

(Also, note that I use `%lx` because vuln is an x86_64 binary. This will give me all 8 bytes for each data on the stack!)  

## Arbitrary Reads  

Before we consider how we might read any memory address, first let's figure out how we might read the data at an address not located after the stack.  

The answer is `%s`. Remember the description of `%s`? This format string will essentially allow us to read the data at any address stored on the stack. Meaning, if the 14th data on the stack stored the address 0x401550, and the flag was written at 0x401550, we could send `"%14$s` to read the flag!  

But how can we utilize this idea to read any memory address, even ones that aren't stored on the stack?  

Well, in vuln, note that buf, i.e. the user input, it stored on the stack. That means we can actually reference the string we input. So, what if we input the address we want to read ourself, and then use %s to read it?  

Let's say buf starts at the 10th offset on the stack. We want to read the address 0x401550. This is how I would do it in pwntools:  

```py
from pwn import *

p = process('./vuln')

'''
NOTE:
Usually, you won't just know where buf starts on the stack. You have to find it! This can be easily accomplished by sending many "%lx|" until you see your input (in hexadecimal form).  
'''
# p.send(b'%lx|'*40)
# p.interactive()

payload = b'%11$s' + b'A'*3 + flat(0x401550)
p.send(payload)

p.interactive()
```

Let's go through the payload construction. `%11$s` reads whatever is in the address stored at the 11th offset on the stack. `AAA` serves as padding to fill the rest of the 8 bytes that make up the 10th data on the stack, since this is an x86_64 binary. Then, `flat(0x401550)` is basically a handy pwntools way to pack the address in little-endian format and pad it to 8 bytes. Note that this will essentially put the address 0x401550 into the 11th offset on the stack, since the 10th offset is already filled. Hence, `%11$s` will retrieve the data stored at 0x401550 and print it out for us!  

**Important!** - You have to put the format specifiers to perform the arbitrary before the address! This is because printf stops printing when it reaches a null byte, and addresses almost always contain null bytes (basically like leading zeros, in this case). If the address is before the format specifiers, the printf will never reach the format specifiers, and never print out the data you want!  

#### Before you move on...

Take a pause here and make sure you fully understand what's going on. Play around with your own program! Write some data into the `.bss` section, or any other section of readable memory that's *not* the stack, and try and perform an arbitrary read.  

## Arbitrary Writes

TODO