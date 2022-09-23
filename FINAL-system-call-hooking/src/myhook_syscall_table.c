/**
 * @file myhook_kallsyms.c
 * @author Wei-Ting Chen aka Nickchen Nick (nickchen120235@gmail.com)
 * @brief a simple syscall hooking example using kallsyms_lookup_name
 * @date 2021-06-11
 * 
 * Tested Environment: Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-74-generic x86_64)
 * 
 * NOTE: This method no longer works for kernel version >= 5.7.0, see https://lwn.net/Articles/813350/ for more info.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>

MODULE_LICENSE("GPL");

static unsigned long* __sys_call_table;

/**
 * @brief original sys_clone prototype, refer to include/linux/syscall.h for more info
 * 
 */
typedef asmlinkage long (*orig_clone_t)(unsigned long, unsigned long, int __user*, int __user*, unsigned long);
orig_clone_t orig_clone;


/**
 * @brief a clone of original write_cr0 function without WP-bit-writing check
 * 
 * @param cr0 cr0 value to be written
 */
inline void my_write_cr0(unsigned long cr0) {
  asm volatile("mov %0,%%cr0" : "+r"(cr0) : : "memory");
}

/**
 * @brief disable write protection
 * 
 */
static inline void disable_wp(void) {
  pr_info("[hook] disable write protection\n");
  unsigned long cr0 = read_cr0();
  clear_bit(16, &cr0);
  my_write_cr0(cr0);
}

/**
 * @brief enable write protection
 * 
 */
static inline void enable_wp(void) {
  pr_info("[hook] enable write protection\n");
  unsigned long cr0 = read_cr0();
  set_bit(16, &cr0);
  my_write_cr0(cr0);
}

/**
 * @brief modified sys_clone
 * 
 */
asmlinkage long my_sys_clone(unsigned long flags, unsigned long newsp, int __user* parent_tidptr, int __user* child_tidptr, unsigned long tls) {
  pr_info("[hook.clone] sys_clone is hooked, caller: %s\n", current->comm);
  return orig_clone(flags, newsp, parent_tidptr, child_tidptr, tls);
}

static int __init my_init(void) {
  __sys_call_table = kallsyms_lookup_name("sys_call_table");
  if (!__sys_call_table) {
    pr_err("[hook] sys_call_table not found! exiting...\n");
    return -1;
  }
  pr_info("[hook] sys_call_table found at 0x%lx\n", __sys_call_table);

  pr_info("[hook] changing syscalls\n");
  disable_wp();
  orig_clone = (orig_clone_t)__sys_call_table[__NR_clone];
  __sys_call_table[__NR_clone] = (unsigned long) my_sys_clone;
  pr_info("[hook] sys_clone changed from 0x%lx to 0x%lx\n", (unsigned long)orig_clone, __sys_call_table[__NR_clone]);
  enable_wp();
  pr_info("[hook] successfully hooked\n");

  return 0;
}

static void __exit my_exit(void) {
  pr_info("[hook] restoring syscalls...\n");
  disable_wp();
  __sys_call_table[__NR_clone] = (unsigned long) orig_clone;
  enable_wp();
  pr_info("[hook] unloaded\n");
}

module_init(my_init);
module_exit(my_exit);

