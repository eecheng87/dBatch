#ifndef LINUX_BATCH_H /* define syscall_t batch(), batcha?() for user space */
#define LINUX_BATCH_H /* and syscall_t __NR_batch for the kernel module. */

#include <asm/unistd.h>                 /* __NR_* */
#define __NR_batch_flush  183    /* Hijack Andrew FS call slot for now */
#define __NR_register 184               /* Do register routine before using batch */

/* config Debug mode */
#define DEBUG 0

/* batch table entry info */
#define BENTRY_EMPTY 0
#define BENTRY_BUSY 1

#define MAX_THREAD_NUM 10
#define MAX_ENTRY_NUM 64

struct batch_entry {
    unsigned pid; /* or thread id */
    short nargs;
    short rstatus;
    unsigned sysnum;
    unsigned sysret;
    long args[6];
};

#ifndef __KERNEL__
#include <errno.h>                      /* needed by syscall macro */
#ifndef syscall
#   include <unistd.h>                  /* syscall() */
#endif

static inline long batch_register(struct batch_entry* table)
{
	syscall(__NR_register, table);
}

#define scall0(N,FL,Z,P            ) ((syscall_t){__NR_##N,FL,Z,P,0 })
#define scall1(N,FL,Z,P,A          ) ((syscall_t){__NR_##N,FL,Z,P,1,(long)(A) })
#define scall2(N,FL,Z,P,A,B        ) ((syscall_t){__NR_##N,FL,Z,P,2,(long)(A),(long)(B) })
#define scall3(N,FL,Z,P,A,B,C      ) ((syscall_t){__NR_##N,FL,Z,P,3,(long)(A),(long)(B),(long)(C) })
#define scall4(N,FL,Z,P,A,B,C,D    ) ((syscall_t){__NR_##N,FL,Z,P,4,(long)(A),(long)(B),(long)(C),(long)(D) })
#define scall5(N,FL,Z,P,A,B,C,D,E  ) ((syscall_t){__NR_##N,FL,Z,P,5,(long)(A),(long)(B),(long)(C),(long)(D),(long)(E) })
#define scall6(N,FL,Z,P,A,B,C,D,E,F) ((syscall_t){__NR_##N,FL,Z,P,6,(long)(A),(long)(B),(long)(C),(long)(D),(long)(E),(long)(F)})
#endif /* __KERNEL__ */
#endif /* LINUX_BATCH_H */
