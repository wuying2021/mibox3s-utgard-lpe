# Cross-compilers (override on the command line if yours are named differently)
CC32 ?= arm-linux-gnueabihf-gcc
CC64 ?= aarch64-linux-gnu-gcc
CFLAGS ?= -O1 -static -Wall -Wextra

# Mi Box 3S chain (this firmware): run.sh uses the aarch64 pair.
# gpwrite64 replaces the ion-based gpu_arb_write because /dev/ion mmap is
# broken here (every mapping returns 0x400008), and kfunc_new is the 64-bit
# caller that reaches the real sys_call_table instead of compat_sys_call_table.
# kread is the 3-argument caller used when re-deriving addresses
# (FINDING_ADDRESSES.md).  Same sources as upstream, just built for aarch64.
BINS := gpwrite64 kfunc_new kread crash_for_core gpu_arb_write gpu_scan

.PHONY: all zig clean install

all: gpwrite64 kfunc_new kread crash_for_core

gpwrite64: src/gpwrite.c
	$(CC64) $(CFLAGS) -o $@ $<

kfunc_new: src/kfunc.c
	$(CC64) $(CFLAGS) -o $@ $<

kread: src/kread.c
	$(CC64) $(CFLAGS) -o $@ $<

crash_for_core: src/crash_for_core.c
	$(CC32) $(CFLAGS) -o $@ $<

# Kept from upstream: the ion-based writer and the address scanner.
gpu_arb_write: src/gpu_arb_write.c
	$(CC32) $(CFLAGS) -o $@ $<

gpu_scan: src/gpu_scan.c
	$(CC32) $(CFLAGS) -o $@ $<

# Same thing via zig, which needs no preinstalled cross toolchain.
ZIG ?= zig
zig:
	ZIG_GLOBAL_CACHE_DIR=$${ZIG_GLOBAL_CACHE_DIR:-/tmp/zigcache} $(ZIG) cc \
		-target aarch64-linux-musl $(CFLAGS) -o gpwrite64 src/gpwrite.c
	ZIG_GLOBAL_CACHE_DIR=$${ZIG_GLOBAL_CACHE_DIR:-/tmp/zigcache} $(ZIG) cc \
		-target aarch64-linux-musl $(CFLAGS) -o kfunc_new src/kfunc.c
	ZIG_GLOBAL_CACHE_DIR=$${ZIG_GLOBAL_CACHE_DIR:-/tmp/zigcache} $(ZIG) cc \
		-target aarch64-linux-musl $(CFLAGS) -o kread src/kread.c
	ZIG_GLOBAL_CACHE_DIR=$${ZIG_GLOBAL_CACHE_DIR:-/tmp/zigcache} $(ZIG) cc \
		-target arm-linux-musleabihf $(CFLAGS) -o crash_for_core src/crash_for_core.c
	ZIG_GLOBAL_CACHE_DIR=$${ZIG_GLOBAL_CACHE_DIR:-/tmp/zigcache} $(ZIG) cc \
		-target arm-linux-musleabihf $(CFLAGS) -o gpu_arb_write src/gpu_arb_write.c
	ZIG_GLOBAL_CACHE_DIR=$${ZIG_GLOBAL_CACHE_DIR:-/tmp/zigcache} $(ZIG) cc \
		-target arm-linux-musleabihf $(CFLAGS) -o gpu_scan src/gpu_scan.c

# Push to a device that is already reachable over adb.
PUSH := gpwrite64 kfunc_new kread crash_for_core run.sh roothelper.sh root_cmd.sh
install: all
	adb push $(PUSH) /data/local/tmp/
	adb shell 'cd /data/local/tmp && chmod 755 $(PUSH)'

clean:
	rm -f $(BINS)
