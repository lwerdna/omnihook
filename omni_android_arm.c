#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/list.h> /* list_head, etc. */
#include <linux/slab.h> /* kmalloc(), kfree(), etc. */
#include <linux/delay.h> /* for msleep() */
#include <linux/kallsyms.h>

#include <asm/pgtable.h> /* PAGE_KERNEL_EXEC */

#include "omnihook.h"

/* master list of all hooks created */
struct list_head hook_list;
LIST_HEAD(hook_list);

/* necessary function pointers */
int mem_protection_syms = 0;
void (*mem_text_writeable_spinlock)(unsigned long *flags);
void (*mem_text_address_writeable)(unsigned long addr);
void (*mem_text_address_restore)(void);
void (*mem_text_writeable_spinunlock)(unsigned long *flags);

int
omnihook_add(void *src, void *dst, /* out */ void **trampoline)
{
    int rc = -1;
    hook *h = NULL;
    unsigned long flags;
    uint8_t *tramp = NULL;
    uint8_t jmpcode[8] = {
        0x04, 0xf0, 0x1f, 0xe5, /* ldr pc, [pc, #-4] */
        0xde, 0xad, 0xbe, 0xef /* (dummy address) */
    };

    if(!mem_protection_syms) {
        mem_text_writeable_spinlock = 
            (void *)kallsyms_lookup_name("mem_text_writeable_spinlock");

        mem_text_address_writeable = 
            (void *)kallsyms_lookup_name("mem_text_address_writeable");

        mem_text_address_restore = 
            (void *)kallsyms_lookup_name("mem_text_address_restore");

        mem_text_writeable_spinunlock = 
            (void *)kallsyms_lookup_name("mem_text_writeable_spinunlock");

        if(mem_text_writeable_spinlock && mem_text_address_writeable &&
            mem_text_address_restore && mem_text_writeable_spinunlock) {

            mem_protection_syms = 1;
        }
        else {
            printk("ERROR: could not resolve memory protection symbols, bailing!\n");
            goto cleanup;
        }
    }

    /* list entry */
    h = kzalloc(sizeof(hook), GFP_KERNEL);
    if(!h) {
        goto cleanup;
    }
    
    /* 1) save info about destination, source */
    h->dst = dst;
    h->src = src;
    memcpy(h->stolen, src, 8);

    /* 2) allocate, build the trampoline:
        <stolen instr 0>
        <stolen instr 1>
        <ldr pc, [pc, #0]>
        <dst>
    */
    tramp = (uint8_t *) __vmalloc(8 + 8, GFP_KERNEL, PAGE_KERNEL_EXEC);
    if(!tramp) {
        goto cleanup;
    }

    //printk("stolen bytes:\n");
    //hexdump(h->stolen, 8);
    memcpy(tramp, h->stolen, 8); /* stolen instructions */
    *(uint32_t *)(jmpcode + 4) = (uint32_t)(src + 8); /* return over the JMP! */
    memcpy(tramp + 8, jmpcode, 8);
    h->trampoline = tramp;
    *trampoline = (void *)tramp;

    /* 3) write the JMP over the source (actually hooking) */
    *(uint32_t *)(jmpcode + 4) = (uint32_t)dst;

    mem_text_writeable_spinlock(&flags);
    mem_text_address_writeable((unsigned long)src);
    memcpy(src, jmpcode, 8); 
    mem_text_address_restore();
    mem_text_writeable_spinunlock(&flags);

    /* debugging */
    printk("omnihook!\n");
    printk("src: 0x%p\n", h->src);
    printk("dst: 0x%p\n", h->dst);
    printk("trampoline: 0x%p\n", h->trampoline);
  
    /* add the omnihook bookkeeping structure */
    list_add(/* address of list member within new element */ &(h->list),
        /* the list_head to add it to */ &hook_list);

    rc = 0;

    cleanup:
    if(0 != rc) {
        if(h) {
            if(h->trampoline) {
                vfree(h->trampoline);
                h->trampoline = NULL;
            }

            kfree(h);
            h = NULL;
        }
    }

    return rc;
}

/* when address is given (non-NULL), it remove single hook from this address
    when address is not given (ie value NULL), it removes all hooks in the list */
int 
omnihook_remove_general(void *src)
{
    int rc = -1;

    int remove, do_break;
    hook *cursor, *temp;

    /* scan thru list of omnihook_list, finding info to properly deallocate */
    list_for_each_entry_safe(/* cursor (it uses this type) */ cursor, 
        /* temporary storage (for the safety feature) */ temp, /* list head */ &hook_list, 
        /* member within, hehe TWSS */ list) {

        remove = 0;
        do_break = 0;

        if(src) {
            printk("src specified, looking for one hook...\n");
            /* if source specified, only remove this one */
            if(cursor->src == src) {
                printk("FOUND!\n");
                remove = 1;
                do_break = 1;
            }
        }
        /* otherwise, remove them all */
        else {
            remove = 1;
        }

        if(remove) {
            unsigned long flags;

            printk("removing hook at address 0x%p\n", cursor->src);

            /* restore original bytes (unhook) */
            //printk("restoring STOLEN bytes:");
            mem_text_writeable_spinlock(&flags);
            mem_text_address_writeable((unsigned long)cursor->src);
            memcpy(cursor->src, cursor->stolen, 8);
            mem_text_address_restore();
            mem_text_writeable_spinunlock(&flags);

            /* free the trampoline */
            //printk("free'ing the trampoline...\n");
            if(cursor->trampoline) {
                vfree(cursor->trampoline);
                cursor->trampoline = NULL;
            }

            /* delete from list */
            //printk("deleting from list...\n");
            list_del(&(cursor->list));

            /* delete from mem */
            //printk("deleting entry itself...\n");
            kfree(cursor);
            cursor = NULL;

            /* success? */
            rc = 0;
        }

        if(do_break) {
            /* done */
            break;
        }
    }

    printk("done...\n");

    return rc;
}

int 
omnihook_remove(void *src)
{
    return omnihook_remove_general(src);
}

int
omnihook_remove_all(void)
{
    return omnihook_remove_general(NULL);
}

