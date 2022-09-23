#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <linux/sched/signal.h>
#include <linux/mm.h>
#include <asm/pgtable.h>

int len, temp;
char* msg;
struct proc_dir_entry* mtest;

int command(const char*);
void listvma(void);
void findpage(unsigned long);
void writeval(unsigned long, unsigned long);

struct vm_area_struct* _findvma(unsigned long);
inline int _vmacanwrite(struct vm_area_struct*);
pte_t* _findpte(unsigned long);

static ssize_t myread(struct file* f, char __user* buf, size_t count, loff_t* pos) {
  if (count > temp) count = temp;
  temp = temp - count;
  copy_to_user(buf, msg, count);
  if (count == 0) temp = len;
  return count;
}

static ssize_t mywrite(struct file* f, const char __user* buf, size_t count, loff_t* pos) {
  unsigned long vaddr; unsigned long val;
  copy_from_user(msg, buf, count);
  len = count;
  temp = len;

  switch(command(msg)) {
    case 1:
      pr_info("[mtest] Got command: listvma\n");
      listvma();
      break;
    case 2:
      sscanf(msg, "%*s 0x%lx", &vaddr);
      pr_info("[mtest] Got command: findpage 0x%lx\n", vaddr);
      findpage(vaddr);
      break;
    case 3:
      sscanf(msg, "%*s 0x%lx 0x%lx", &vaddr, &val);
      pr_info("[mtest] Got command: writeval 0x%lx 0x%lx\n", vaddr, val);
      writeval(vaddr, val);
      break;
    default:
      pr_info("[mtest] Unknown command\n");
      break;
  }

  return count;
}

struct file_operations myops = {
  .read = myread,
  .write = mywrite
};

static int __init myinit(void) {
  mtest = proc_create("mtest", 0600, NULL, &myops);
  msg = kmalloc(GFP_KERNEL, 200*sizeof(char));
  pr_info("[mtest] mtest is inserted\n");
  return 0;
}

static void __exit myexit(void) {
  proc_remove(mtest);
  kfree(msg);
  pr_info("[mtest] mtest is removed\n");
}

module_init(myinit);
module_exit(myexit);

int command(const char* cmd) {
  if (strlen(cmd) < 8) return -1;
  if (strncmp(cmd, "listvma" , 7) == 0) return 1;
  if (strncmp(cmd, "findpage", 8) == 0) return 2;
  if (strncmp(cmd, "writeval", 8) == 0) return 3;
  return -1;
}

void listvma(void) {
  struct task_struct* task;
  struct mm_struct* mm;
  struct vm_area_struct* vma_iter;
  unsigned long perm_flags;
  char perm_str[4];
  perm_str[3] = '\0';

  for_each_process(task) if (strncmp(task -> comm, "test", 4) == 0) break;
  pr_info("[mtest.listvma] Process = %s, PID = %d\n", task -> comm, task -> pid);
  mm = task -> mm;
  if (mm != NULL) {
    vma_iter = mm->mmap;
    while (vma_iter) {
      perm_flags = vma_iter -> vm_flags;
      if (perm_flags & VM_READ) perm_str[0] = 'r';
      else perm_str[0] = '-';
      if (perm_flags & VM_WRITE) perm_str[1] = 'w';
      else perm_str[1] = '-';
      if (perm_flags & VM_EXEC) perm_str[2] = 'x';
      else perm_str[2] = '-';
      pr_info("[mtest.listvma] 0x%lx 0x%lx %s", vma_iter -> vm_start, vma_iter -> vm_end, perm_str);
      vma_iter = vma_iter -> vm_next;
    }
  }
}

void findpage(unsigned long vaddr) {
  struct task_struct* task;
  pgd_t* pgd; p4d_t* p4d; pud_t* pud; pmd_t* pmd; pte_t* pte;
  unsigned long paddr; unsigned long page_addr;
  unsigned long page_offset;
  pr_info("[mtest.findpage] vaddr = 0x%lx", vaddr);

  pr_info("[mtest.findpage] pgtable_l5_enabled = %u\n", pgtable_l5_enabled());

  for_each_process(task) if (strncmp(task -> comm, "test", 4) == 0) break;
  pr_info("[mtest.findpage] current = %s, PID = %d", task -> comm, task -> pid);

  pgd = pgd_offset(task -> mm, vaddr);
  pr_info("[mtest.findpage] pgd_val = 0x%lx\n", pgd_val(*pgd));
  pr_info("[mtest.findpage] pgd_index = %lu\n", pgd_index(vaddr));
  if (pgd_none(*pgd)) {
    pr_info("[mtest.findpage] not mapped in pgd\n");
    return;
  }

  p4d = p4d_offset(pgd, vaddr);
  pr_info("[mtest.findpage] p4d_val = 0x%lx\n", p4d_val(*p4d));
  pr_info("[mtest.findpage] p4d_index = %lu\n", p4d_index(vaddr));
  if (p4d_none(*p4d)) {
    pr_info("[mtest.findpage] not mapped in p4d\n");
    return;
  }

  pud = pud_offset(p4d, vaddr);
  pr_info("[mtest.findpage] pud_val = 0x%lx\n", pud_val(*pud));
  pr_info("[mtest.findpage] pud_index = %lu\n", pud_index(vaddr));
  if (pud_none(*pud)) {
    pr_info("[mtest.findpage] not mapped in pud\n");
    return;
  }

  pmd = pmd_offset(pud, vaddr);
  pr_info("[mtest.findpage] pmd_val = 0x%lx\n", pmd_val(*pmd));
  pr_info("[mtest.findpage] pmd_index = %lu\n", pmd_index(vaddr));
  if (pmd_none(*pmd)) {
    pr_info("[mtest.findpage] not mapped in pmd\n");
    return;
  }

  pte = pte_offset_kernel(pmd, vaddr);
  pr_info("[mtest.findpage] pte_val = 0x%lx\n", pte_val(*pte));
  pr_info("[mtest.findpage] pte_index = %lu\n", pte_index(vaddr));
  if (pte_none(*pte)) {
    pr_info("[mtest.findpage] not mapped in pte\n");
    return;
  }

  page_addr = pte_val(*pte) & PAGE_MASK;
  page_offset = vaddr & ~PAGE_MASK;
  paddr = page_addr | page_offset;
  pr_info("[mtest.findpage] page_addr = 0x%lx, page_offset = 0x%lx\n", page_addr, page_offset);
  pr_info("[mtest.findpage] vaddr = 0x%lx -> paddr = 0x%lx\n", vaddr, paddr);
}

void writeval(unsigned long vaddr, unsigned long val) {
  struct vm_area_struct* vma;
  pte_t* pte; void* addr;
  struct page* page;

  vma = _findvma(vaddr);
  if (!vma) {
    pr_info("[mtest.writeval] vma not found\n");
    return;
  }
  if (_vmacanwrite(vma) < 0) {
    pr_info("[mtest.writeval] vma has no write permission\n");
    return;
  }
  pte = _findpte(vaddr);
  if (!pte) {
    pr_info("[mtest.writeval] pte not found\n");
    return;
  }
  page = pte_page(*pte);
  addr = page_address(page);
  pr_info("[mtest.writeval] found\n");
  memset(addr, val, 1);
}

struct vm_area_struct* _findvma(unsigned long vaddr) {
  struct task_struct* task;
  struct mm_struct* mm;
  struct vm_area_struct* vma_iter;

  for_each_process(task) if (strncmp(task -> comm, "test", 4) == 0) break;
  mm = task -> mm;
  if (mm != NULL) {
    vma_iter = mm->mmap;
    while (vma_iter) {
      if (vaddr >= vma_iter -> vm_start && vaddr <= vma_iter -> vm_end) return vma_iter;
      vma_iter = vma_iter -> vm_next;
    }
  }
  return NULL;
}

inline int _vmacanwrite(struct vm_area_struct* vma) {
  if (vma -> vm_flags & VM_WRITE) return 1;
  else return -1;
}

pte_t* _findpte(unsigned long vaddr) {
  struct task_struct* task;
  pgd_t* pgd; p4d_t* p4d; pud_t* pud; pmd_t* pmd; pte_t* pte;

  for_each_process(task) if (strncmp(task -> comm, "test", 4) == 0) break;
  pgd = pgd_offset(task -> mm, vaddr);
  if (pgd_none(*pgd)) return NULL;
  p4d = p4d_offset(pgd, vaddr);
  if (p4d_none(*p4d)) return NULL;
  pud = pud_offset(p4d, vaddr);
  if (pud_none(*pud)) return NULL;
  pmd = pmd_offset(pud, vaddr);
  if (pmd_none(*pmd)) return NULL;
  pte = pte_offset_kernel(pmd, vaddr);
  if (pte_none(*pte)) return NULL;
  return pte;
}