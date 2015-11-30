#include <sys/types.h>
#include <sys/module.h>
#include <sys/systm.h>  /* uprintf */
#include <sys/errno.h>
#include <sys/param.h>  /* defines used in kernel.h */
#include <sys/queue.h>
#include <sys/malloc.h>
#include <sys/kernel.h> /* types used in module initialization */

#include "omnihook.h"

/* declared in omnihook.h (so users extern to it)
    defined here ... use `vmstat -m` to see */
MALLOC_DEFINE(M_HOOKBUF, "hookbuff", "holds hook info and trampolines");

/* type of listed structures is hook_info
    name of list is hook_list */
static SLIST_HEAD(, hook_info) hook_list = SLIST_HEAD_INITIALIZER();

/* prototypes */
void disable_write_protect(void);
void enable_write_protect(void);

//-----------------------------------------------------------------------------
// WRITE PROTECT ENABLE/DISABLE
//-----------------------------------------------------------------------------

void 
disable_write_protect(void)
{
    #if defined(__i386__)
    uint32_t cr0_value;
    __asm__ volatile ("movl %%cr0, %0" : "=r" (cr0_value));
    cr0_value &= ~(1 << 16);
    __asm__ volatile ("movl %0, %%cr0" :: "r" (cr0_value));
    #elif defined(__amd64__)
    uint64_t cr0_value;
    __asm__ volatile ("movq %%cr0, %0" : "=r" (cr0_value));
    cr0_value &= ~(1 << 16);
    __asm__ volatile ("movq %0, %%cr0" :: "r" (cr0_value));
    #else
    #error cannot determine whether i386 or amd64
    #endif
}
        
void 
enable_write_protect(void)
{
    #if defined(__i386__)
    uint32_t cr0_value;
    __asm__ volatile ("movl %%cr0, %0" : "=r" (cr0_value));
    cr0_value |= (1 << 16);
    __asm__ volatile ("movl %0, %%cr0" :: "r" (cr0_value));
    #elif defined(__amd64__)
    uint64_t cr0_value;
    __asm__ volatile ("movq %%cr0, %0" : "=r" (cr0_value));
    cr0_value |= (1 << 16);
    __asm__ volatile ("movq %0, %%cr0" :: "r" (cr0_value));
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

    struct hook hook;
    struct hook_info *info = NULL;
    struct trampoline *tramp = NULL;

    /* list entry */
    info = malloc(sizeof(struct hook_info), M_HOOKBUF, M_NOWAIT);
    if(!info) goto cleanup; 
    
    /* 1) save info about destination, source */
    info->dst = dst;
    info->src = src;

    /* 2) allocate, build the trampoline: */
    tramp = malloc(sizeof(trampoline), M_HOOKBUF, M_NOWAIT);
    if(!tramp) goto cleanup;
    memcpy(tramp, TRAMPOLINE_INIT, sizeof(*tramp));
    memcpy(tramp->stolen, src, sizeof(tramp->stolen));
    tramp->addr = (uintptr_t)src + sizeof(hook); /* absolute address */

    /* inform the hook info struct */
    info->tramp = tramp;
    /* inform the caller */
    *trampoline = (void *)tramp;

    /* 3) write the JMP over the source (actually hooking) */
    memcpy(&hook, HOOK_INIT, sizeof(hook));
    hook.addr = (uintptr_t)dst;
    disable_write_protect();
    memcpy(src, &hook, sizeof(hook)); 
    enable_write_protect();

    /* debugging */
    printf("omnihook!\n");
    printf("src: 0x%p\n", info->src);
    printf("dst: 0x%p\n", info->dst);
    printf("trampoline: 0x%p\n", info->tramp);
  
    /* store the omnihook bookkeeping structure */
    SLIST_INSERT_HEAD(/* pointer to list head */ &hook_list, 
        /* listable struct */ info, 
        /* name of SLIST_ENTRY within listable struct */ next);

    rc = 0;

    cleanup:
    if(0 != rc) {
        /* if we errored, free the trampoline then the hook */
        if(info) {
            if(info->tramp) {
                free(info->tramp, M_HOOKBUF);
                info->tramp = NULL;
            }

            free(info, M_HOOKBUF);
            info = NULL;
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
    struct hook_info *cursor, *temp;

    /* scan thru list of hook_list, finding info to properly deallocate */

    SLIST_FOREACH_SAFE(cursor, &hook_list, next, temp) {
        remove = 0;
        do_break = 0;

        if(src) {
            printf("src specified, looking for one hook...\n");
            /* if source specified, only remove this one */
            if(cursor->src == src) {
                printf("FOUND!\n");
                remove = 1;
                do_break = 1;
            }
        }
        /* otherwise, remove them all */
        else {
            remove = 1;
        }

        if(remove) {
            printf("removing hook at address 0x%p\n", cursor->src);

            /* restore original bytes (unhook) */
            //printf("restoring STOLEN bytes:");
            disable_write_protect();
            memcpy(cursor->src, cursor->tramp->stolen, 
                sizeof(cursor->tramp->stolen));
            enable_write_protect();

            /* free the trampoline */
            printf("free'ing the trampoline...\n");
            if(cursor->tramp) {
                free(cursor->tramp, M_HOOKBUF);
                cursor->tramp = NULL;
            }

            /* delete from list */
            printf("deleting from list...\n");
            SLIST_REMOVE(&hook_list, cursor, hook_info, next);

            /* delete from mem */
            printf("deleting entry itself...\n");
            free(cursor, M_HOOKBUF);
            cursor = NULL;

            /* success? */
            rc = 0;
        }

        if(do_break) {
            /* done */
            break;
        }
    }

    printf("done...\n");

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

