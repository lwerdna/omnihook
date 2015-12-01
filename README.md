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
            |  | <overwritten   |<-+
            |  |  instructions> |
            +--| jmp src+XX     |
               +----------------+
```
* i386, ia64 details:
  * the jumps are made with a push+ret combo (5 bytes)
  * the intel instruction stealing is not very general, it always steals 5 bytes
  * in my experience on Ubuntu, the first instruction in function prologs is 5 bytes
  * better would be to incorporate a small length disassembler engine and steal at least 5 bytes, but end on an instruction boundary, and craft the trampoline accordingly
* arm details:
  * the jumps are made with a ldr pc immediate (8 bytes)
  * 8 bytes is always 2 instructions, so theft is easy

## usage
see example.c

## linux on i386, amd64 (tested: Ubuntu)
* use omni_linux_i386_amd64.{c,h}
* no problems, this is omnihook's home, and you probably can tweak your target machine to accommodate omnihook easier, by exposing kallsyms for example

## linux on arm (tested: raspberry pi)
* use omni_linux_arm.{c,h}

## android on arm (tested: various phones)
* use omni_linux_arm.{c,h}
* phones are so varied in their security, see some of the shit you might have to do in my prdbg project
* consider defining ANDROID_MEM_PROT_NEEDED

## freebsd on i386, amd64 (tested: pcbsd)
* must do some define before malloc(), kind of a pain
* printf() instead of printk()
* familiar {insmod, rmmod, lsmod} becomes {kldload, kldunload, kldstat} here, and kldload needs full path

