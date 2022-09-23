/**
 * @file myhook_kprobe.c
 * @author Wei-Ting Chen aka Nickchen Nick (nickchen120235@gmail.com)
 * @brief syscall hooking using kprobe and ftrace
 * @date 2021-06-11
 * 
 * Tested Environment: Ubuntu 20.04.2 LTS (GNU/Linux 5.8.0-55-generic x86_64)
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>

#define SYSCALL_NAME(name) ("__x64_" name)
#define HOOK(_name, _hook, _orig) { \
  .name = SYSCALL_NAME(_name),      \
  .function = (_hook),              \
  .original = (_orig)               \
}

MODULE_LICENSE("GPL");

static struct kprobe kp = {
  .symbol_name = "kallsyms_lookup_name"
};

typedef struct ftrace_hook {
  const char* name;
  void* function;
  void* original;

  unsigned long address;
  struct ftrace_ops ops;
} ftrace_hook_t;

static int resolve_hook_address(ftrace_hook_t* hook) {
  typedef unsigned long (*kallsyms_lookup_name_t)(const char* name);
  kallsyms_lookup_name_t kallsyms_lookup_name;
  register_kprobe(&kp);
  kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
  unregister_kprobe(&kp);

  if (kallsyms_lookup_name) pr_info("[hook] kallsyms_lookup_name is found at 0x%lx\n", kallsyms_lookup_name);

  hook->address = kallsyms_lookup_name(hook->name);
  if (!hook->address) {
    pr_err("[hook] unresolved symbol: %s\n", hook->name);
    return -1;
  }

  pr_info("[hook] symbol %s found\n", hook->name);
  *((unsigned long*) hook->original) = hook->address;
  return 0;
}

static void notrace ftrace_thunk(unsigned long ip, unsigned long parent_ip, struct ftrace_ops* ops, struct pt_regs* regs) {
  ftrace_hook_t* hook = container_of(ops, ftrace_hook_t, ops);
  if (!within_module(parent_ip, THIS_MODULE)) regs->ip = (unsigned long) hook->function; // recursion prevention
}

int install_hook(ftrace_hook_t* hook) {
  int err;
  err = resolve_hook_address(hook);
  if (err) return err;

  hook->ops.func = ftrace_thunk;
  hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY;
  err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
  if (err) {
    pr_err("[hook] ftrace_set_filter_ip() failed: %d\n", err);
    return err;
  }

  err = register_ftrace_function(&hook->ops);
  if (err) {
    pr_err("[hook] register_ftrace_function() failed: %d\n", err);
    return err;
  }

  return 0;
}

void remove_hook(ftrace_hook_t* hook) {
  int err;
  err = unregister_ftrace_function(&hook->ops);
  if (err) pr_err("[hook] unregister_ftrace_function() failed: %d\n", err);

  err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
  if (err) pr_err("[hook] ftrace_set_filter_ip() failed: %d\n", err);
}

typedef asmlinkage long (*orig_clone_t)(unsigned long, unsigned long, int __user*, int __user*, unsigned long);
orig_clone_t orig_clone;

asmlinkage long my_sys_clone(unsigned long flags, unsigned long newsp, int __user* parent_tidptr, int __user* child_tidptr, unsigned long tls) {
  pr_info("[hook.clone] sys_clone is hooked, caller: %s\n", current->comm);
  return orig_clone(flags, newsp, parent_tidptr, child_tidptr, tls);
}

static ftrace_hook_t sys_clone_hook = HOOK("sys_clone", my_sys_clone, &orig_clone);

static int __init myinit(void) {
  int err;
  err = install_hook(&sys_clone_hook);
  if (err) return err;
  pr_info("[hook] hooked\n");
  return 0;
}

static void __exit myexit(void) {
  remove_hook(&sys_clone_hook);
  pr_info("[hook] removed\n");
}

module_init(myinit);
module_exit(myexit);

