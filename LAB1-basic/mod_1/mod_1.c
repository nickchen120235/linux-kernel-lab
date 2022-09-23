#include <linux/init.h>   // macro
#include <linux/module.h> // needed for all module
#include <linux/kernel.h> // KERN_INFO

static int __init hello(void) {
  printk(KERN_INFO "*****HELLO*****\n");
  return 0;
}

static void __exit bye(void) {
  printk(KERN_INFO "*****BYEBYE*****\n");
}

module_init(hello); // hello will be executed upon insmod
module_exit(bye);   // bye will be executed upon rmmod