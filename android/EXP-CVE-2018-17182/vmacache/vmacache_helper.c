#undef __KERNEL__
#define __KERNEL__
#undef MODULE
#define MODULE

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/kallsyms.h>
#include <linux/blkdev.h>
#include <linux/mm.h>
#include <linux/vmacache.h>
#include <linux/sched/signal.h>
#include "vmacache_helper.h"

static int ioctl_open(struct inode *nodp, struct file *filp) {
  return 0;
}

void vmacache_debug_dump(void)
{
 struct mm_struct *mm = current->mm;
 struct task_struct *g, *p;
 int i;

 pr_warn("entering vmacache_debug_dump(0x%lx)\n", (unsigned long)mm);
 pr_warn("  mm sequence: 0x%x\n", mm->vmacache_seqnum);
 rcu_read_lock();
 for_each_process_thread(g, p) {
   if (mm == p->mm) {
     pr_warn("  task 0x%lx at 0x%x%s\n", (unsigned long)p,
       p->vmacache.seqnum,
       (current == p)?" (current)":"");
     pr_warn("    cache dump:\n");
     for (i=0; i<VMACACHE_SIZE; i++) {
       unsigned long vm_start, vm_end, vm_mm;
       int err = 0;

       pr_warn("      0x%lx\n",
         (unsigned long)p->vmacache.vmas[i]);
       err |= probe_kernel_read(&vm_start,
         &p->vmacache.vmas[i]->vm_start,
         sizeof(unsigned long));
       err |= probe_kernel_read(&vm_end,
         &p->vmacache.vmas[i]->vm_end,
         sizeof(unsigned long));
       err |= probe_kernel_read(&vm_mm,
         &p->vmacache.vmas[i]->vm_mm,
         sizeof(unsigned long));
       if (err)
         continue;
       pr_warn("        start=0x%lx end=0x%lx mm=0x%lx\n",
         vm_start, vm_end, vm_mm);
     }
   }
 }
 rcu_read_unlock();
 pr_warn("  #####\n");
}

static long ioctl_handler(struct file *filp_, unsigned int cmd, unsigned long arg) {
  void __user *argp = (void __user *)arg;

  switch (cmd) {
    case GET_VMA_PTR: {
      struct get_vma_args args;
      struct vm_area_struct *vma;

      if (copy_from_user(&args, argp, sizeof(args)))
        return -EFAULT;
      vma = find_vma(current->mm, args.mapping_addr);
      if (!vma || vma->vm_start > args.mapping_addr)
        return -ENOENT;
      args.vma_addr = (unsigned long)vma;
      if (copy_to_user(argp, &args, sizeof(args)))
        return -EFAULT;
      return 0;
    } break;
    case DUMP_VMA: {
      struct dump_vma_args args;
      struct vm_area_struct *vma;
      if (copy_from_user(&args, argp, sizeof(args)))
        return -EFAULT;
      vma = (void*)args.vma_addr;

      /* if this is too unstable, use probe_kernel_read() */
      args.vm_start = vma->vm_start;
      args.vm_end = vma->vm_end;
      args.vm_mm = vma->vm_mm;
      args.vm_page_prot = vma->vm_page_prot.pgprot;
      args.vm_flags = vma->vm_flags;
      args.vm_ops = vma->vm_ops;
      args.vm_pgoff = vma->vm_pgoff;
      args.vm_file = vma->vm_file;
      args.vm_private_data = vma->vm_private_data;

      if (copy_to_user(argp, &args, sizeof(args)))
        return -EFAULT;
      return 0;
    } break;
    case FORCE_VMA: {
      char tmp[1];
      int res;

      pr_warn("FORCE_VMA mm=0x%lx\n", (unsigned long)current->mm);
      current->vmacache.vmas[0] = (void*)arg;
      current->vmacache.vmas[1] = (void*)arg;
      current->vmacache.vmas[2] = (void*)arg;
      current->vmacache.vmas[3] = (void*)arg;
      current->vmacache.seqnum = current->mm->vmacache_seqnum;

      res = copy_from_user(tmp, (void __user *)0x100, 1);
      pr_warn("copy_from_user: %d\n", res);

      current->vmacache.vmas[0] = NULL;
      current->vmacache.vmas[1] = NULL;
      current->vmacache.vmas[2] = NULL;
      current->vmacache.vmas[3] = NULL;

      return 0;
    } break;
    case DMESG_DUMP: {
      vmacache_debug_dump();
      return 0;
    } break;
    case SEQUENCE_BUMP: {
      current->mm->vmacache_seqnum += arg;
      return 0;
    } break;
    default: return -EINVAL;
  }
}

static int ioctl_release(struct inode *nodp, struct file *filp) {
  return 0;
}

static const struct file_operations ioctl_fops = {
  .owner = THIS_MODULE,
  .unlocked_ioctl = ioctl_handler,
  .open = ioctl_open,
  .release = ioctl_release
};

static struct miscdevice my_miscdev = {
  .minor = 0,
  .name = "vmacache",
  .fops = &ioctl_fops
};

static int __init init_mod(void) {
  int ret;
  printk(KERN_INFO "loading helper module\n");

  ret = misc_register(&my_miscdev);
  return ret;
}

static void __exit cleanup_ioctl(void) {
  printk(KERN_INFO "unloading helper module\n");
  misc_deregister(&my_miscdev);
}

module_init(init_mod);
module_exit(cleanup_ioctl);

MODULE_LICENSE("GPL v2");
