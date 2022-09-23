#include <linux/init.h>        // macro
#include <linux/module.h>      // needed for all module
#include <linux/moduleparam.h> // module_param
#include <linux/kernel.h>      // KERN_INFO

// parameter holder
static int my_int = 0;
static char* my_string = "DEFAULT";
int my_int_array[5];
static int my_int_array_count = 0;

// parameter declaration
module_param(my_int, int, 0644);
module_param(my_string, charp, 0644);
module_param_array(my_int_array, int, &my_int_array_count, 0644);

static int __init hello(void) {
  printk(KERN_INFO "****[mod_2 is installed]****\n");
  printk(KERN_INFO "[mod_2] my_int = %d\n", my_int);
  printk(KERN_INFO "[mod_2] my_string = %s\n", my_string);
  printk(KERN_INFO "[mod_2] my_int_array_count = %d\n", my_int_array_count);
  int i = 0;
  for (i = 0; i < (sizeof my_int_array / sizeof (int)); ++i) {
    printk(KERN_INFO "[mod_2] my_int_array[%d] = %d\n", i, my_int_array[i]);
  }

  return 0;
}

static void __exit bye(void) {
  printk(KERN_INFO "****[mod_2 is removed]****\n");
}

module_init(hello);
module_exit(bye);