/* linux hooking example */

#include "omnihook_linux_i386_amd64.h"

void (*trampoline_input_event)(void *dev, unsigned int type, 
    unsigned int code, int value);

void
detour_input_event(void *dev, unsigned int type, unsigned int code, int value)
{
    /* prove we worked */
    printk("IT WORKS!\n");

    /* pass execution through */
    return trampoline_input_event(dev, type, code, value);
}

static int __init 
example_init(void)
{
    int rc = -1;
    uintptr_t addr;   

    /* resolve target function */
    addr = kallsyms_lookup_name("input_event");
    if(!addr) { 
        printk("ERROR: resolving input_event()\n"); 
        goto cleanup; 
    }

    /* hook it */
    omnihook_add((void *)addr, detour_input_event, (void **)&trampoline_input_event);

    rc = 0;

    cleanup:
    return rc;
}

static void __exit 
example_exit(void)
{
    /* unhook all */
    omnihook_remove_all();
}

module_init(example_init);
module_exit(example_exit);

MODULE_LICENSE("GPL");
