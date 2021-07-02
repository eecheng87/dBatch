#include "preload.h"
//int curindex[MAX_THREAD_NUM];
int curindex = 1;
int table_size = 64;
int main_thread_pid;
int in_segment;
void *mpool; /* memory pool */
int pool_offset;
int batch_num; /* number of busy entry */


int off, toff;

long batch_start() {
    in_segment = 1;
    if(!btable){
    int pgsize = getpagesize();
    btable =
        (struct batch_entry *)aligned_alloc(pgsize, pgsize);
    toff = (((struct pthread_fake *)pthread_self())->tid - main_thread_pid);
    toff -= 1;
    printf("Register table %d\n", toff);
    off = toff << 6;
    syscall(__NR_register, btable, toff);
    }
    return 0;
}

long batch_flush() {
    in_segment = 0;
    /* avoid useless batch_flush */
    if(batch_num == 0)
        return 0;
    //printf("flushing %d (from user space)\n", batch_num);
    batch_num = 0;
    return syscall(__NR_batch_flush, toff);
}

int close(int fd) {

    if (!in_segment) {
        real_close = real_close ? real_close : dlsym(RTLD_NEXT, "close");
        return real_close(fd);
    }
    batch_num++;

    /*int off,
        toff = (((struct pthread_fake *)pthread_self())->tid - main_thread_pid);
    toff -= 1;
    off = toff << 6;*/
    //off = 0;
    //toff = 0;
    //printf(">> this is worker %d\n", toff);
    btable[/*off + curindex[toff]*/curindex].sysnum = __NR_close;
    btable[/*off + curindex[toff]*/curindex].rstatus = BENTRY_BUSY;
    btable[/*off + curindex[toff]*/curindex].nargs = 1;
    btable[/*off + curindex[toff]*/curindex].args[0] = fd;
    btable[/*off + curindex[toff]*/curindex].pid = main_thread_pid + off;
    //curindex[toff] =
      //  (curindex[toff] == MAX_TABLE_SIZE - 1) ? 1 : curindex[toff] + 1;
    curindex = (curindex == MAX_TABLE_SIZE - 1) ? 1 : curindex + 1;
    if(batch_num > 60)
	    batch_flush();
    return 0;
}


ssize_t sendfile64(int outfd, int infd, off_t* offset, size_t count){
    //printf("-> sendfile(%d,%d,%ld,%ld)\n", outfd, infd, offset, count);
    //real_sendfile = dlsym(RTLD_NEXT, "sendfile");
    /*if (!in_segment) {
        real_sendfile = real_sendfile ? real_sendfile : dlsym(RTLD_NEXT, "sendfile64");
        return real_sendfile(outfd, infd ,offset, count);
    }*/
    //return real_sendfile(outfd, infd, offset, count);
    batch_num++;

    /*int off,
        toff = (((struct pthread_fake *)pthread_self())->tid - main_thread_pid);
    toff -= 1;
    off = toff << 6;*/
//printf("fill index %d\n", off + curindex[toff]);
    //off = 0;
    //toff = 0;
    //printf(">> this is worker %d\n", toff);
    btable[/*off + curindex[toff]*/curindex].sysnum = 40;
    btable[/*off + curindex[toff]*/curindex].rstatus = BENTRY_BUSY;
    btable[/*off + curindex[toff]*/curindex].nargs = 4;
    btable[/*off + curindex[toff]*/curindex].args[0] = outfd;
    btable[/*off + curindex[toff]*/curindex].args[1] = infd;
    btable[/*off + curindex[toff]*/curindex].args[2] = offset;
    btable[/*off + curindex[toff]*/curindex].args[3] = count;
    btable[/*off + curindex[toff]*/curindex].pid = main_thread_pid + off;
    //curindex[toff] =
      //  (curindex[toff] == MAX_TABLE_SIZE - 1) ? 1 : curindex[toff] + 1;
    curindex = (curindex == MAX_TABLE_SIZE - 1) ? 1 : curindex + 1;
    /* assume always success */
    return count;
}
#if 0
#include <sched.h>
int epoll_wait(int epfd, struct epoll_event *events, 
		int maxevent, int timeout)
{
   //real_ep_w = real_ep_w ? real_ep_w : dlsym(RTLD_NEXT, "epoll_wait");
    while(1){
	//printf("vd_avail = %d\n", fastpoll());
	if(fastpoll() != 0){
	//	printf("vd_avail = %d\n", fastpoll());
		break;
	}
	sched_yield();
    }

    return syscall(232, epfd, events, maxevent, timeout);
}
#endif

void ctrl_c_hdlr(int s)
{
	printf("\nClean up...\n");
        syscall(404);
	exit(1);	
}

__attribute__((constructor)) static void setup(void) {
    int i;
    size_t pgsize = getpagesize();
    in_segment = 0;
    batch_num = 0;

    /* init memory pool */
    mpool = (void*)malloc(sizeof(unsigned char) * MAX_POOL_SIZE);
    pool_offset = 0;

    /* get pid of main thread */
    main_thread_pid = syscall(186);

    //btable =
      //  (struct batch_entry *)aligned_alloc(pgsize, pgsize * MAX_THREAD_NUM);

    //syscall(__NR_register, btable);
    signal(SIGINT, ctrl_c_hdlr);

    //for (i = 0; i < MAX_THREAD_NUM; i++)
      //  curindex[i] = 1;
}
