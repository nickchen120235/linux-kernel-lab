#include <linux/init.h>    // marco
#include <linux/module.h>  // needed for all modules
#include <linux/kernel.h>  // KERN_INFO
#include <linux/proc_fs.h> // proc filesystem
#include <linux/uaccess.h> // kernel space to user space

#define BUFSIZE 100

static struct proc_dir_entry* myproc;

static ssize_t mywrite(struct file* f, const char __user* ubuf, size_t count, loff_t* ppos) {
  printk(KERN_INFO "[mod_3] mywrite\n");
  return -EROFS;
}

static ssize_t myread(struct file* f, char __user* ubuf, size_t count, loff_t* ppos) {
  char buf[BUFSIZE];
  int len = 0;
  printk(KERN_INFO "[mod_3] myread\n");
  if (*ppos > 0 || count < BUFSIZE) return 0;
  len += sprintf(buf, "THIS IS MYPROC!!\n");

  if (copy_to_user(ubuf, buf, len)) return -EFAULT;
  *ppos = len;
  return len;
}

static struct file_operations myops = {
  .owner = THIS_MODULE,
  .read = myread,
  .write = mywrite
};

static int __init myinit(void) {
  printk(KERN_INFO "*****[mod_3 is installed]*****\n");
  myproc = proc_create("my_readonly_proc", 0600, NULL, &myops);
  printk(KERN_INFO "[mod_3] created /proc/my_readonly_proc\n");
  return 0;
}

static void __exit myexit(void) {
  proc_remove(myproc);
  printk(KERN_INFO "*****[mod_3 is removed]*****\n");
}

module_init(myinit);
module_exit(myexit);