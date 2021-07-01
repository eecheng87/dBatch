#include <generated/asm-offsets.h> /* __NR_syscall_max */
#include <linux/batch.h>
#include <linux/kallsyms.h> /* kallsyms_lookup_name, __NR_* */
#include <linux/kernel.h>   /* Basic Linux module headers */
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/uaccess.h> /* copy_from_user put_user */
#include <linux/version.h>

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

    /* map batch table from user-space to kernel */
    n_page = get_user_pages(
        (unsigned long)(p1), /* Start address to map */
        MAX_THREAD_NUM, /* Number of pinned pages. 4096 btyes in this machine */
        FOLL_FORCE | FOLL_WRITE, /* Force flag */
        pinned_pages,            /* struct page ** pointer to pinned pages */
        NULL);

    for (i = 0; i < MAX_THREAD_NUM; i++)
        batch_table[i] = (struct batch_entry *)kmap(pinned_pages[i]);

    /* initial table status */
    for (j = 0; j < MAX_THREAD_NUM; j++)
        for (i = 0; i < MAX_ENTRY_NUM; i++)
            batch_table[j][i].rstatus = BENTRY_EMPTY;

    for (i = 0; i < MAX_THREAD_NUM; i++)
        start_index[i] = 1;

    main_pid = current->pid;

    return 0;
}

/* printk is only for debug usage */
/* it will lower a lot performance */
asmlinkage long sys_batch(const struct pt_regs *regs) {
    int j = current->pid - main_pid;
    unsigned long i = start_index[j];

#if DEBUG
    printk(KERN_INFO "Start flushing (at [%d][%lu]), called from %d\n", j, i, main_pid + j); 
#endif
    while (batch_table[j][i].rstatus == BENTRY_BUSY) {
#if DEBUG
        printk(KERN_INFO "Index %ld do syscall %d\n", i,
               batch_table[j][i].sysnum);
#endif
        /*switch (batch_table[j][i].sysnum) {
        case __NR_write:
        case __NR_read:
        case __NR_close: {
            int fd = batch_table[j][i].args[0];
            batch_table[j][i].args[0] =
                fd < 0 ? batch_table[j][-fd].sysret : fd;
            break;
        }
        default:
            break;
        }*/
        batch_table[j][i].sysret =
            indirect_call(scTab[batch_table[j][i].sysnum],
                          batch_table[j][i].nargs, batch_table[j][i].args);
        batch_table[j][i].rstatus = BENTRY_EMPTY;
//	printk(KERN_INFO "sendfile(%ld,%ld,%ld,%ld);ret = %d\n", batch_table[j][i].args[0], batch_table[j][i].args[1], batch_table[j][i].args[2], batch_table[j][i].args[3], batch_table[j][i].sysret);
        i = (i == 63) ? 1 : i + 1;
    }
    start_index[j] = i;
    return 0;
}

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

void *sys_oldcall0;
void *sys_oldcall1;
void *syscall_emp_ori;
void *syscall_emp_ori2;

static struct Vdso_data* vd;
static struct vdso_data* vvar;
asmlinkage long sys_fpreg(const struct pt_regs *regs) {
	printk("regist fpoll\n");
	
	vvar = (struct vdso_data*)(vdsoDataAddr + ((char *)&system_wq - sysWQ));;
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
    printk(KERN_INFO "batch: removed\n");

    /* correspond cleanup for kmap */
    kunmap(pinned_pages[0]);
}
module_init(mod_init);
module_exit(mod_cleanup);
