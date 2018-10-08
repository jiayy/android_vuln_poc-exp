#define GET_VMA_PTR 0x13370000
struct get_vma_args {
  unsigned long mapping_addr;
  unsigned long vma_addr;
};

#define DUMP_VMA 0x13370001
struct dump_vma_args {
  unsigned long vma_addr;

  unsigned long vm_start;
  unsigned long vm_end;

  struct mm_struct *vm_mm;
  unsigned long vm_page_prot;
  unsigned long vm_flags;

  const struct vm_operations_struct *vm_ops;

  unsigned long vm_pgoff;
  struct file * vm_file;
  void * vm_private_data;
};

#define FORCE_VMA 0x13370002

#define DMESG_DUMP 0x13370003

#define SEQUENCE_BUMP 0x13370004
