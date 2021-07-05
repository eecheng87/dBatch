#include <generated/asm-offsets.h> /* __NR_syscall_max */
//#include <linux/batch.h>
#include <linux/kallsyms.h> /* kallsyms_lookup_name, __NR_* */
#include <linux/kernel.h>   /* Basic Linux module headers */
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/uaccess.h> /* copy_from_user put_user */
#include <linux/version.h>
#include "../include/linux/batch.h"
#include <linux/file.h>
#include <linux/fs.h>
#include <asm/vdso/vsyscall.h>


#include "scTab.h"

MODULE_DESCRIPTION("Generic batch system call API");
MODULE_AUTHOR("Steven Cheng");
MODULE_LICENSE("GPL v2");

struct page *pinned_pages[MAX_THREAD_NUM];

typedef asmlinkage long (*F0_t)(void);
typedef asmlinkage long (*F1_t)(long);
typedef asmlinkage long (*F2_t)(long, long);
typedef asmlinkage long (*F3_t)(long, long, long);
typedef asmlinkage long (*F4_t)(long, long, long, long);
typedef asmlinkage long (*F5_t)(long, long, long, long, long);
typedef asmlinkage long (*F6_t)(long, long, long, long, long, long);

static inline long
indirect_call(void *f, int argc,
              long *a) { /* x64 syscall calling convention changed @4.17 to use
                            struct pt_regs */
    struct pt_regs regs;
    memset(&regs, 0, sizeof regs);
    switch (argc) {
    case 6:
        regs.r9 = a[5]; /* Falls through. */
    case 5:
        regs.r8 = a[4]; /* Falls through. */
    case 4:
        regs.r10 = a[3]; /* Falls through. */
    case 3:
        regs.dx = a[2]; /* Falls through. */
    case 2:
        regs.si = a[1]; /* Falls through. */
    case 1:
        regs.di = a[0]; /* Falls through. */
    }
    return ((F1_t)f)((long)&regs);
}

static void **scTab = 0;
struct batch_entry *batch_table[MAX_THREAD_NUM];
int table_size = 64;
int start_index[MAX_THREAD_NUM];
int main_pid; /* PID of main thread */

asmlinkage long sys_register(const struct pt_regs *regs) {
    printk(KERN_INFO "Start register, address at regs is %p\n", regs);
    int n_page, i, j;
    unsigned long p1 = regs->di;
    long wkr = regs->si;

    /* map batch table from user-space to kernel */
    n_page = get_user_pages(
        (unsigned long)(p1), /* Start address to map */
        /*MAX_THREAD_NUM*/ 1, /* Number of pinned pages. 4096 btyes in this machine */
        FOLL_FORCE | FOLL_WRITE, /* Force flag */
        &pinned_pages[wkr],            /* struct page ** pointer to pinned pages */
        NULL);

    //for (i = 0; i < MAX_THREAD_NUM; i++)
        batch_table[wkr] = (struct batch_entry *)kmap(pinned_pages[wkr]);

    /* initial table status */
    //for (j = 0; j < MAX_THREAD_NUM; j++)
        for (i = 0; i < MAX_ENTRY_NUM; i++)
            batch_table[wkr][i].rstatus = BENTRY_EMPTY;

    //for (i = 0; i < MAX_THREAD_NUM; i++)
        start_index[wkr] = 1;

    //main_pid = current->pid;

    return 0;
}

/* printk is only for debug usage */
/* it will lower a lot performance */
int infd = -1;
asmlinkage long sys_batch(const struct pt_regs *regs) {
    int j = regs->di;
    unsigned long i = start_index[j];
    //int infd = -1;
#if DEBUG
    printk(KERN_INFO "Start flushing (at [%d][%lu]), called from %d\n", j, i, j); 
#endif
    while (batch_table[j][i].rstatus == BENTRY_BUSY) {
#if DEBUG
        //printk(KERN_INFO "Index %ld do syscall %d\n", i,
          //     batch_table[j][i].sysnum);
#endif
        /*switch (batch_table[j][i].sysnum) {
	case __NR_sendfile:{
	    if(infd > 0)
	        batch_table[j][i].args[1] = infd;
	    break;	    
	}
        default:
            break;
        }*/
        batch_table[j][i].sysret =
            indirect_call(scTab[batch_table[j][i].sysnum],
                          batch_table[j][i].nargs, batch_table[j][i].args);
        batch_table[j][i].rstatus = BENTRY_EMPTY;
	/*if (batch_table[j][i].sysnum == 257){
	char bb[200];
	bb[199] = 0;
	strncpy_from_user(bb, batch_table[j][i].args[1], 199);
	printk("file name is %s\n", bb);
            infd = batch_table[j][i].sysret;
          
        }*/

#if DEBUG
	printk(KERN_INFO "syscall(%d, %ld,%ld,%ld,%ld);ret = %d\n", batch_table[j][i].sysnum, batch_table[j][i].args[0], batch_table[j][i].args[1], batch_table[j][i].args[2], batch_table[j][i].args[3], batch_table[j][i].sysret);
#endif
	i = (i == 63) ? 1 : i + 1;
    }
    start_index[j] = i;
    return 0;
}

#if defined(__x86_64__)
extern unsigned long __force_order __weak;
#define store_cr0(x) asm volatile("mov %0,%%cr0" : "+r"(x), "+m"(__force_order))
static void allow_writes(void) {
    unsigned long cr0 = read_cr0();
    clear_bit(16, &cr0);
    store_cr0(cr0);
}
static void disallow_writes(void) {
    unsigned long cr0 = read_cr0();
    set_bit(16, &cr0);
    store_cr0(cr0);
}
#elif defined(__aarch64__)
static struct mm_struct *init_mm_ptr;
// From arch/arm64/mm/pageattr.c.
struct page_change_data {
    pgprot_t set_mask;
    pgprot_t clear_mask;
};

// From arch/arm64/mm/pageattr.c.
static int change_page_range(pte_t *ptep, unsigned long addr, void *data)
{
    struct page_change_data *cdata = data;
    pte_t pte = READ_ONCE(*ptep);

    pte = clear_pte_bit(pte, cdata->clear_mask);
    pte = set_pte_bit(pte, cdata->set_mask);

    set_pte(ptep, pte);
    return 0;
}

// From arch/arm64/mm/pageattr.c.
static int __change_memory_common(unsigned long start, unsigned long size,
                  pgprot_t set_mask, pgprot_t clear_mask)
{
    struct page_change_data data;
    int ret;

    data.set_mask = set_mask;
    data.clear_mask = clear_mask;

    ret = apply_to_page_range(init_mm_ptr, start, size, change_page_range, &data);

    flush_tlb_kernel_range(start, start + size);
    return ret;
}

// Simplified set_memory_rw() from arch/arm64/mm/pageattr.c.
static int set_page_rw(unsigned long addr)
{
    vm_unmap_aliases();
    return __change_memory_common(addr, PAGE_SIZE, __pgprot(PTE_WRITE), __pgprot(PTE_RDONLY));
}

// Simplified set_memory_ro() from arch/arm64/mm/pageattr.c.
static int set_page_ro(unsigned long addr)
{
    vm_unmap_aliases();
    return __change_memory_common(addr, PAGE_SIZE, __pgprot(PTE_RDONLY), __pgprot(PTE_WRITE));
}

static void allow_writes(void) {
    set_page_rw((unsigned long)(syscall_table + __NR_emp) & PAGE_MASK);
}
static void disallow_writes(void) {
    set_page_ro((unsigned long)(syscall_table + __NR_emp) & PAGE_MASK);
}
static void enable_cycle_counter_el0(void* data)
{
	u64 val;
	/* Disable cycle counter overflow interrupt */
	asm volatile("msr pmintenset_el1, %0" : : "r" ((u64)(0 << 31)));
	/* Enable cycle counter */
	asm volatile("msr pmcntenset_el0, %0" :: "r" BIT(31));
	/* Enable user-mode access to cycle counters. */
	asm volatile("msr pmuserenr_el0, %0" : : "r"(BIT(0) | BIT(2)));
	/* Clear cycle counter and start */
	asm volatile("mrs %0, pmcr_el0" : "=r" (val));
	val |= (BIT(0) | BIT(2));
	isb();
	asm volatile("msr pmcr_el0, %0" : : "r" (val));
	val = BIT(27);
	asm volatile("msr pmccfiltr_el0, %0" : : "r" (val));
}

static void disable_cycle_counter_el0(void* data)
{
	/* Disable cycle counter */
	asm volatile("msr pmcntenset_el0, %0" :: "r" (0 << 31));
	/* Disable user-mode access to counters. */
	asm volatile("msr pmuserenr_el0, %0" : : "r"((u64)0));

}
#endif


void *sys_oldcall0;
void *sys_oldcall1;
void *syscall_emp_ori;
void *syscall_emp_ori2;

static struct Vdso_data* vd;
static struct vdso_data* vvar;
asmlinkage long sys_fpreg(const struct pt_regs *regs) {
	printk("regist fpoll\n");
	
	vvar = (struct vdso_data*)(vdsoDataAddr + ((char *)&system_wq - smSysWQ));
	int epfd;
       	struct fd f;
	epfd = regs->di;
	f = fdget(epfd);
	if(!f.file)
		return -1;
    allow_writes();
	vvar[0].__ep_addr = f.file->private_data;
	vvar[0].__ep_avail = 0;
    disallow_writes();
        return 0;
}
asmlinkage long sys_fpexit(const struct pt_regs *regs) {
    printk("exit fpoll\n");
    allow_writes();
    vvar[0].__ep_addr = 0;
	vvar[0].__ep_avail = 0;
    disallow_writes();
    return 0;
}

static int __init mod_init(void) {

    /* hook system call */
    scTab = (void **)(smSCTab + ((char *)&system_wq - smSysWQ));
#if defined(__aarch64__) 
    init_mm_ptr = (struct mm_struct *)(sysMM + ((char *)&system_wq - smSysWQ));
    on_each_cpu(enable_cycle_counter_el0, NULL, 1);
#endif


    allow_writes();

    /* backup */
    sys_oldcall0 = scTab[__NR_batch_flush];
    sys_oldcall1 = scTab[__NR_register];
    syscall_emp_ori = (void *)scTab[__NR_fpreg];
    syscall_emp_ori2 = (void *)scTab[__NR_fpexit];

    /* hooking */
    scTab[__NR_batch_flush] = sys_batch;
    scTab[__NR_register] = sys_register;
    scTab[__NR_fpreg] = (void *)sys_fpreg;
    scTab[__NR_fpexit] = (void *)sys_fpexit;

    disallow_writes();

    printk(KERN_INFO "batch: installed as %d\n", __NR_batch_flush);

    return 0;
}
static void __exit mod_cleanup(void) {
    allow_writes();

    /* restore */
    scTab[__NR_batch_flush] = sys_oldcall0;
    scTab[__NR_register] = sys_oldcall1;
    scTab[__NR_fpreg] = (void *)syscall_emp_ori;
    scTab[__NR_fpexit] = (void *)syscall_emp_ori2;

    disallow_writes();

#if defined(__aarch64__)
    init_mm_ptr = (struct mm_struct *)(sysMM + ((char *)&system_wq - smSysWQ));
    on_each_cpu(disable_cycle_counter_el0, NULL, 1);
#endif
    printk(KERN_INFO "batch: removed\n");

    /* correspond cleanup for kmap */
    kunmap(pinned_pages[0]);
}
module_init(mod_init);
module_exit(mod_cleanup);
