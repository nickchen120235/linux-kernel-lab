# Linux Kernel Lab

## [LAB 1: Basic Linux Kernel Module Development](https://github.com/nickchen120235/linux-kernel-lab/tree/master/LAB1-basic)
1. [basic `module_init`, `module_exit` usage](https://github.com/nickchen120235/linux-kernel-lab/tree/master/LAB1-basic)
2. [module parameters](https://github.com/nickchen120235/linux-kernel-lab/blob/master/LAB1-basic/mod_2/mod_2.c)
3. [read-only proc file](https://github.com/nickchen120235/linux-kernel-lab/blob/master/LAB1-basic/mod_3/mod_3.c)
4. [read-writable proc file](https://github.com/nickchen120235/linux-kernel-lab/blob/master/LAB1-basic/mod_4/mod_4.c)

## [LAB 2: Scheduling](https://github.com/nickchen120235/linux-kernel-lab/tree/master/LAB2-scheduling)
Add scheduling counter by modifying the kernel and recompile it
1. add counter variable in `struct task_struct` in `include/linux/sched.h`
2. initialize the counter (set to 0) in `kernel_clone()` in `kernel/fork.c`
3. increase the counter by 1 in `activate_task()` in `kernel/sched/core.c`
4. create a entry in `tgid_base_stuff[]` in `fs/proc/base.c`

See [https://nickchen120235.github.io/2021/04/22/linux-kernel-scheduling.html](https://nickchen120235.github.io/2021/04/22/linux-kernel-scheduling.html) for more details

## [LAB 3: Memory Management](https://github.com/nickchen120235/linux-kernel-lab/tree/master/LAB3-memory-management)
Three memory management-related functionalities implemented for both [x86](https://github.com/nickchen120235/linux-kernel-lab/tree/master/LAB3-memory-management/x86) and [aarch64](https://github.com/nickchen120235/linux-kernel-lab/tree/master/LAB3-memory-management/aarch64) architectures
- `listvma`: print all virtual addresses of all processes in the format of `start-addr end-addr permission`
- `findpage addr`: print the corresponding physical address of virtual address `addr`. If no such translation exists, print `translation not found`
- `writeval addr val`: try to write `val` to `addr`

See [https://nickchen120235.github.io/2021/05/18/linux-kernel-memory-management.html](https://nickchen120235.github.io/2021/05/18/linux-kernel-memory-management.html) for more details

## [LAB 4: File System](https://github.com/nickchen120235/linux-kernel-lab/tree/master/LAB4-file-system)
Modify romfs implementation to accomplish the following functionalities
- hide a file: modify [`romfs_readdir`](https://github.com/nickchen120235/linux-kernel-lab/blob/f27f3850cce84b9534b8943b643c47455545c6eb/LAB4-file-system/src/super.c#L187)
- encrypt a file: modify [`romfs_readpage`](https://github.com/nickchen120235/linux-kernel-lab/blob/f27f3850cce84b9534b8943b643c47455545c6eb/LAB4-file-system/src/super.c#L116)
- change the permission of a file: modify [`romfs_lookup`](https://github.com/nickchen120235/linux-kernel-lab/blob/f27f3850cce84b9534b8943b643c47455545c6eb/LAB4-file-system/src/super.c#L263)

## [Final Project: Linux System Call Hooking](https://github.com/nickchen120235/linux-kernel-lab/tree/master/FINAL-system-call-hooking)
Two methods for hooking
- [modify `sys_call_table`](https://github.com/nickchen120235/linux-kernel-lab/blob/master/FINAL-system-call-hooking/src/myhook_syscall_table.c)
- [`ftrace`](https://github.com/nickchen120235/linux-kernel-lab/blob/master/FINAL-system-call-hooking/src/myhook_ftrace.c)
- [bonus: use `kprobe` to find unexported `kallsyms_lookup_name`](https://github.com/nickchen120235/linux-kernel-lab/blob/f27f3850cce84b9534b8943b643c47455545c6eb/FINAL-system-call-hooking/src/myhook_ftrace.c#L38)
