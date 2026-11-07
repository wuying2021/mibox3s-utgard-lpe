/* crash_for_core - raise RLIMIT_CORE and die with SIGSEGV so the kernel runs
 * the core_pattern pipe helper. */
#include <sys/resource.h>
#include <unistd.h>

int main(void)
{
    struct rlimit r;
    r.rlim_cur = RLIM_INFINITY;
    r.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_CORE, &r);
    *(volatile int *)0 = 1; /* SIGSEGV */
    return 0;
}
