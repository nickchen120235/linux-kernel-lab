#include <linux/module.h>  // needed for all modules
#include <linux/kernel.h>  // kernel thing
#include <linux/proc_fs.h> // working with proc filesystem
#include <linux/slab.h>    // memory management
#include <linux/uaccess.h> // user <-> kernel space

int len, temp;
char* msg;
struct proc_dir_entry* parent;

static ssize_t myread(struct file* f, char __user* buf, size_t count, loff_t* pos) {
  printk(KERN_INFO "[mod_4] myread\n");
  if (count > temp) count = temp;
  temp = temp - count;
  printk(KERN_INFO "[mod_4] count = %d, temp = %d, len = %d\n", count, temp, len);
  copy_to_user(buf, msg, count);
  if (count == 0) temp = len;
  printk(KERN_INFO "[mod_4] count = %d, temp = %d, len = %d\n", count, temp, len);
  return count;
}

static ssize_t mywrite(struct file* f, const char __user* buf, size_t count, loff_t* pos) {
  printk(KERN_INFO "[mod_4] mywrite\n");
  copy_from_user(msg, buf, count);
  printk(KERN_INFO "[mod_4] count = %d, temp = %d, len = %d\n", count, temp, len);
  len = count;
  temp = len;
  return count;
}

struct file_operations myops = {
  .read = myread,
  .write = mywrite
};

static int __init myinit(void) {
  printk(KERN_INFO "*****[mod_4 is installed]*****\n");
  parent = proc_mkdir("myproc_folder", NULL);
  proc_create("myproc", 0600, parent, &myops);
  msg = kmalloc(GFP_KERNEL, 100*sizeof(char));
  printk(KERN_INFO "[mod_4] created /proc/myproc_folder/myproc\n");
  return 0;
}

static void __exit myexit(void) {
  proc_remove(parent);
  kfree(msg);
  printk(KERN_INFO "*****[mod_4 is removed]*****\n");
}

module_init(myinit);
module_exit(myexit);