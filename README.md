# omnihook
* convenient inline (instruction replacing) hooking library
* intended to be compiled as a kernel module (see my prdbg_linux project for the same strategy implemented in python)
* detour functions (functions that execute in place of the hooked function) are written in C, no asm required
* trampoline is made for you to call hooked function with original (pre hook) behavior
* can be added and removed without limit

## strategy
* "src" is the function you want to hook
* "dst" is your function to be called instead of src
* "trampoline" is function dynamically allocated by omnihook that can be called to pass execution to src without the intervening hook
```
 "src"                                 "dst"
+-------+                             +-----------+
| jmp ------------------------------->|???        |
| instr |<--+                         |...        |
| ...   |   |   "trampoline"       +--|src_orig() |
+-------+   |  +----------------+  |  +-----------+
            |  | <overwritten   |  |
            |  |  instructions> |  |
            +--| jmp src+XX     |--+
               +----------------+
```

## usage
see example.c

## linux on i386, amd64
no problems, this is omnihook's home, and you probably can tweak your target machine to accommodate omnihook (exposing kallsyms, etc.)

## android on arm (phones)
* phones are so varied in their security, see some of the shit you might have to do in my prdbg project
* you may be able to disable mem_protection_syms

## linux on arm (raspberry pi)
coming soon

## freebsd on i386, amd64
* must do some define before malloc(), kind of a pain
* printf() instead of printk()
* familiar {insmod, rmmod, lsmod} becomes {kldload, kldunload, kldstat} here, and kldload needs full path

