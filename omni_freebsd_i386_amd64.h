MALLOC_DECLARE(M_HOOKBUF);

#if defined(__i386__)
struct trampoline {
    /* 0x00: */
    unsigned char stolen[5];
    /* 0x05: 68 XX XX XX XX ; pushq <imm> */
    unsigned char push[1];
    uintptr_t addr_bounce_to;
    /* 0x0A: C3             ; retq */
    unsigned char ret[1];
    /* 0x0B: (total size: 11 bytes) */
} __attribute__((packed));

#define TRAMPOLINE_INIT \
    "\x00\x00\x00\x00\x00" \
    "\x68\xAA\xAA\xAA\xAA" \
    "\xC3"

#elif defined(__amd64__)

struct hook {
    /* 0x00: */
    unsigned char pushq[6];
    /* 0x06: */
    unsigned char retq[1];
    /* 0x07: */
    uintptr_t addr;
    /* 0x0F: */
    uint8_t pad[2];
    /* 0x11: (total size: 17 bytes) */
} __attribute__((packed));

#define HOOK_INIT \
    "\xFF\x35\x01\x00\x00\x00" \
    "\xC3" \
    "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA" \
    "\x90\x90"

struct trampoline {
    /* 0x00: */
    unsigned char stolen[sizeof(struct hook)];
    /* 0x06: FF 35 01 00 00 00 ; pushq 0x1(%rip) */
    unsigned char pushq[6];
    /* 0x0C: C3             ; retq */
    unsigned char retq[1];
    /* 0x0D: */
    uintptr_t addr;
    /* 0x15: (total size: 15 bytes) */
} __attribute__((packed));

#define TRAMPOLINE_INIT \
    "\x00\x00\x00\x00\x00\x00\x00\x00" \
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
    "\xFF\x35\x01\x00\x00\x00" \
    "\xC3" \
    "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"

#else
#error cannot determine whether i386 or amd64
#endif

struct hook_info {
    SLIST_ENTRY(hook_info) next;
    void *src; // address where JMP is written
    void *dst; // address where JMP lands
    struct trampoline *tramp; // address where clean trampoline allocated
};

int omnihook_add(void *src, void *dst, /* out */ void **thunk);
int omnihook_remove(void *src);
int omnihook_remove_general(void *src);
int omnihook_remove_all(void);


