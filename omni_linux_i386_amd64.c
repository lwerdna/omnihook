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

//-----------------------------------------------------------------------------
// WRITE PROTECT ENABLE/DISABLE
//-----------------------------------------------------------------------------

void 
disable_write_protect(void)
{
    #if defined(__i386__)
    uint32_t cr0_value;
    asm volatile ("movl %%cr0, %0" : "=r" (cr0_value));
    cr0_value &= ~(1 << 16);
    asm volatile ("movl %0, %%cr0" :: "r" (cr0_value));
    #elif defined(__amd64__)
    uint64_t cr0_value;
    asm volatile ("movq %%cr0, %0" : "=r" (cr0_value));
    cr0_value &= ~(1 << 16);
    asm volatile ("movq %0, %%cr0" :: "r" (cr0_value));
    #else
    #error cannot determine whether i386 or amd64
    #endif
}
        
void 
enable_write_protect(void)
{
    #if defined(__i386__)
    uint32_t cr0_value;
    asm volatile ("movl %%cr0, %0" : "=r" (cr0_value));
    cr0_value |= (1 << 16);
    asm volatile ("movl %0, %%cr0" :: "r" (cr0_value));
    #elif defined(__amd64__)
    uint64_t cr0_value;
    asm volatile ("movq %%cr0, %0" : "=r" (cr0_value));
    cr0_value |= (1 << 16);
    asm volatile ("movq %0, %%cr0" :: "r" (cr0_value));
    #else
    #error cannot determine whether i386 or amd64
    #endif
}

//-----------------------------------------------------------------------------
// HOOKLIB MAIN API
//-----------------------------------------------------------------------------
int
omnihook_add(void *src, void *dst, /* out */ void **trampoline)
{
    int rc = -1;
    hook *h = NULL;
    uint8_t *tramp = NULL;

    uint8_t jmpcode[5] = {
        0xe9, /* jmp XXX */
        0xde, 0xad, 0xbe, 0xef /* (dummy address) */
    };

    /* list entry */
    h = kzalloc(sizeof(hook), GFP_KERNEL);
    if(!h) {
        goto cleanup;
    }
    
    /* 1) save info about destination, source */
    h->dst = dst;
    h->src = src;
    memcpy(h->stolen, src, sizeof(h->stolen));

    /* 2) allocate, build the trampoline: */

    #if defined(__i386__)
    /* x86 TRAMPOLINE:
        00: <stolen 5 bytes>
        05: 68                ; push <imm>
        06: <4-byte absolute address>
        10: c3                ; ret
        11:
    */
    tramp = (uint8_t *) __vmalloc(11, GFP_KERNEL, PAGE_KERNEL_EXEC);
    if(!tramp) goto cleanup;

    memcpy(tramp, h->stolen, sizeof(h->stolen)); /* stolen instructions */
    *(unsigned char *)(tramp + 5) = 0x68; /* the push */
    *(uintptr_t *)(tramp + 6) = src + 5; /* absolute address */
    *(unsigned char *)(tramp + 10) = 0xc3; /* ret */
	#elif defined(__amd64__)
    /* x64 TRAMPOLINE:
        00: <stolen 5 bytes>
        05: FF 35 01 00 00 00 ; pushq 0x1(%rip)
        11: c3                ; retq
        12: <8-byte absolute address>
        20:
    */
    tramp = (uint8_t *) __vmalloc(20, GFP_KERNEL, PAGE_KERNEL_EXEC);
    if(!tramp) goto cleanup;

    memcpy(tramp, h->stolen, sizeof(h->stolen)); /* stolen instructions */
    memcpy(tramp + 5, "\xff\x35\x01\x00\x00\x00\xc3", 7); /* the pushq, retq */
    *(uintptr_t *)(tramp + 12) = src + 5; /* the absolute address */
    #else
    #error cannot determine whether i386 or amd64
    #endif

    /* inform the hook struct */
    h->trampoline = tramp;
    /* inform the caller */
    *trampoline = (void *)tramp;

    /* 3) write the JMP over the source (actually hooking) */
    *(uint32_t *)(jmpcode + 1) = dst - (src+5);
    disable_write_protect();
    memcpy(src, jmpcode, 5); 
    enable_write_protect();

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

    /* scan thru list of hook_list, finding info to properly deallocate */
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
            printk("removing hook at address 0x%p\n", cursor->src);

            /* restore original bytes (unhook) */
            //printk("restoring STOLEN bytes:");
            disable_write_protect();
            memcpy(cursor->src, cursor->stolen, sizeof(cursor->stolen));
            enable_write_protect();

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

