# SM-X900 / X900XXSBEZE1 port record

## Status

```text
model: SM-X900
device: gts8x
region/CSC: EUX
AP/PDA: X900XXSBEZE1
display build: BP2A.250605.031.A3.X900XXSBEZE1
Android SDK: 36
ABI: arm64-v8a
page size: 4096
kernel release: 5.10.236-android12-9-32140295-abX900XXSBEZE1
SoC: Qualcomm SM8450 (Snapdragon 8 Gen 1)
security patch: 2026-05-05
```

The exploit profile is **structurally complete** — all struct layout offsets have
been derived from the Samsung android12-5.10 kernel source for SM8450
(`akm-04/Samsung_Kernel_sm8450_common_gts8x`, branch `common_android12-5.10`,
kernel 5.10.226). Struct layouts are identical between 5.10 sublevel patches.

**Symbol offsets are NOT yet populated.** The 21 kernel symbol addresses marked
`EXTRACT` in `target.h` must be recovered from the SM-X900 firmware binary
(boot.img → vmlinux → kallsyms). The P0 fingerprint table is likewise empty.

No values in this profile were copied from the 6.1 or 6.6 targets.

## SoC and physical memory map

The SM-X900 uses the Qualcomm SM8450 (Snapdragon 8 Gen 1, codename "waipio").
DRAM base on SM8450 is `0x80000000` (standard Qualcomm layout).

```text
P0_PHYS_OFFSET:       0x80000000  (SM8450 DRAM base — verify from DTB)
P0_KERNEL_PHYS_LOAD:  0x80000000  (verify from boot.img header kernel_addr)
KIMAGE_TEXT_BASE:     0xffffffc008000000  (standard arm64)
P0_PAGE_OFFSET:       0xffffff8000000000  (standard arm64 VA39)
```

**Verification required:** Extract `kernel_addr` from the boot.img header using
`unpackbootimg -i boot.img`. If the header reports a different load address,
update `P0_KERNEL_PHYS_LOAD` accordingly.

## Firmware extraction (TODO)

The firmware `X900XXSBEZE1` (EUX region, security patch 2026-05-05) must be
downloaded from Samsung's FUS or a mirror site (samfw.com, OdinRom).

```text
# Download firmware:
samloader -m SM-X900 -r EUX download --latest --auto-decrypt

# Or use samloader-rs:
samloader-rs download SM-X900 EUX --latest
```

Expected extraction flow:

```text
AP_X900XXSBEZE1_*.tar → boot.img.lz4 → boot.img
  unpackbootimg -i boot.img → kernel (gzip or lz4 compressed)
  lz4 -d kernel → Image  (or gzip -d kernel → Image)
```

SHA-256 hashes: **to be recorded after extraction.**

## Symbol recovery (TODO)

Once the raw ARM64 Image is extracted:

```bash
# Recover vmlinux with symbols
vmlinux-to-elf Image vmlinux.elf

# Extract kallsyms symbol table
kallsyms-finder Image > kallsyms.txt

# Count expected symbols (should be ~100k+)
wc -l kallsyms.txt
```

### Required symbol offsets

All offsets are relative to `KIMAGE_TEXT_BASE` (`0xffffffc008000000`).
Search for these symbol names in the kallsyms output:

| Symbol name | target.h macro | Description |
| --- | --- | --- |
| ashmem_misc (fops field) | `ASHMEM_MISC_FOPS_OFF` | miscdevice fops pointer |
| ashmem_fops | `ASHMEM_FOPS_OFF` | ashmem file_operations |
| ashmem_ioctl | `ASHMEM_IOCTL_OFF` | ashmem_ioctl function |
| compat_ashmem_ioctl | `ASHMEM_COMPAT_IOCTL_OFF` | compat ioctl |
| ashmem_mmap | `ASHMEM_MMAP_OFF` | ashmem_mmap |
| ashmem_open | `ASHMEM_OPEN_OFF` | ashmem_open |
| ashmem_release | `ASHMEM_RELEASE_OFF` | ashmem_release |
| ashmem_show_fdinfo | `ASHMEM_SHOW_FDINFO_OFF` | show_fdinfo |
| configfs_read_file | `CONFIGFS_READ_ITER_OFF` | configfs read iter |
| configfs_write_bin_file | `CONFIGFS_BIN_WRITE_ITER_OFF` | configfs bin write |
| generic_file_splice_read | `COPY_SPLICE_READ_OFF` | splice read |
| noop_llseek | `NOOP_LLSEEK_OFF` | noop_llseek |
| init_task | `INIT_TASK_OFF` | init_task |
| root_task_group | `ROOT_TASK_GROUP_OFF` | root_task_group |
| selinux_state | `SELINUX_ENFORCING_OFF` | selinux enforcing |
| kmalloc_caches | `KMALLOC_CACHES_OFF` | kmalloc_caches |
| anon_pipe_buf_ops | `ANON_PIPE_BUF_OPS_OFF` | pipe buf ops |
| call_usermodehelper_exec_work | `CALL_USERMODEHELPER_EXEC_WORK_OFF` | UMH exec work |
| system_unbound_wq | `SYSTEM_UNBOUND_WQ_OFF` | unbound workqueue |
| nfulnl_logger (name string) | `SLIDE_NFULNL_LOGGER_NAME_OFF` | netfilter logger name |
| nfulnl_logger (struct) | `SLIDE_NFULNL_LOGGER_OBJECT_OFF` | netfilter logger object |
| boot_id sysctl data ptr | `SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF` | boot_id data |
| sysctl_bootid | `SLIDE_SYSCTL_BOOTID_OFF` | boot UUID storage |

Compute each as: `offset = symbol_addr - 0xffffffc008000000`

### SLIDE configuration (TODO)

```text
SLIDE_TRACEFS_EVENT_ID:          (read from /sys/kernel/debug/tracing/events/sched/sched_blocked_reason/id)
SLIDE_TRACEFS_WORKER_CALLER_OFF: (disassemble worker_thread, find instruction after bl schedule)
```

## 5.10 struct layout (verified from source)

The struct layouts below are derived from the Samsung SM8450 kernel source
(`common_android12-5.10` branch) and are identical to the A15 5.10.226 target.
The android12-5.10 GKI base config is standardized across Samsung ARM64 devices.

### rt_mutex_waiter (legacy 0x50-byte layout)

```text
0x00  struct rb_node    tree_entry       (24 bytes)
0x18  struct rb_node    pi_tree_entry    (24 bytes)
0x30  struct task_struct *task           (8 bytes)
0x38  struct rt_mutex   *lock            (8 bytes)
0x40  int               prio             (4 bytes)
0x44  (padding)                          (4 bytes)
0x48  u64               deadline         (8 bytes)
                                   total: 0x50
```

CONFIG_DEBUG_RT_MUTEXES is disabled in production Samsung builds.

### task_struct (critical field offsets)

```text
0x040  refcount_t  usage
0x084  int         prio
0x08c  int         normal_prio
0x310  struct task_group *sched_task_group  (CONFIG_CGROUP_SCHED)
0x86c  raw_spinlock_t    pi_lock
0x880  struct rb_root_cached pi_waiters
0x890  struct task_struct   *pi_top_task
0x898  struct rt_mutex_waiter *pi_blocked_on
```

### Allocator config

```text
mm_struct size:           0x3c0  (smaller than 6.1's 0x500)
mm_struct slab order:     3
kmalloc_caches types:     2      (normal + reclaim only)
kmalloc cgroup type:      0      (not type 2 as in 6.1)
```

## KernelSU

The 5.10 KernelSU module from the A15 port should be compatible:

```text
Module: kernelsu/android12-5.10_kernelsu-samsung-kdp.ko  (361,328 bytes)
Daemon: kernelsu/ksud-samsung-android12-5.10-kdp         (6,649,032 bytes)
```

Both use KernelSU v3.2.5 with Samsung KDP/RKP/DEFEX patches. The 5.10
build uses `cred->user->processes` (not `cred->ucounts`) and zero-length
`__versions` with runtime kallsyms resolution due to CONFIG_TRIM_UNUSED_KSYMS.

**Verification:** Run `tools/audit_module_against_target.py` against the
SM-X900 vmlinux to confirm all 208 undefined symbols resolve. The vermagic
must be patched to match `5.10.236-android12-9-32140295-abX900XXSBEZE1`.

## Cross-reference

The SM-X900 uses Snapdragon 8 Gen 1 (SM8450), shared with:
- Galaxy S22 series (SM-S90x) — same SoC, different kernel build
- Galaxy Tab S8 (SM-X700) — same Tab S8 kernel source tree
- Galaxy Tab S8+ (SM-X800) — same Tab S8 kernel source tree

The kernel source repository `akm-04/Samsung_Kernel_sm8450_common_gts8x`
covers all three Tab S8 variants. Symbol offsets from other SM8450 devices
will NOT match (different build numbers) but struct layouts are identical.

## P0 fingerprint (TODO)

The P0 fingerprint table requires the raw kernel Image binary.
Generate with:

```bash
perl tools/generate_p0_fingerprint.pl \
  <kernel_Image> \
  <KIMAGE_TEXT_BASE + P0_ORACLE_GATE_PAGE_OFF>
```

The placeholder table in `p0_fingerprint.h` has 32 zero rows; the P0 oracle
will fail until populated with real fingerprint data from the SM-X900 kernel.
