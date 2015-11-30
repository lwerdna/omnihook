typedef struct hook_ {
    struct list_head list;
    void *src; // address where JMP is written
    void *dst; // address where JMP lands
    void *trampoline; // address where clean trampoline allocated
    unsigned char stolen[5]; // bytes stolen at JMP write location
} hook;

int
omnihook_add(void *src, void *dst, /* out */ void **thunk);

int 
omnihook_remove(void *src);

int
omnihook_remove_all(void);
