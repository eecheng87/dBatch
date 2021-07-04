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
struct batch_entry *btable;
long batch_start(int events) {
    //if(events < 10)return 0;
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

    btable[/*off + curindex[toff]*/curindex].sysnum = __NR_close;
    btable[/*off + curindex[toff]*/curindex].rstatus = BENTRY_BUSY;
    btable[/*off + curindex[toff]*/curindex].nargs = 1;
    btable[/*off + curindex[toff]*/curindex].args[0] = fd;
    curindex = (curindex == MAX_TABLE_SIZE - 1) ? 1 : curindex + 1;
    if(batch_num > 50)
	    batch_flush();
    return 0;
}


ssize_t sendfile64(int outfd, int infd, off_t* offset, size_t count){
	//real_sendfile = dlsym(RTLD_NEXT, "sendfile");
   if (!in_segment) {
        real_sendfile = real_sendfile ? real_sendfile : dlsym(RTLD_NEXT, "sendfile");
        return real_sendfile(outfd, infd ,offset, count);
    }
    //return real_sendfile(outfd, infd, offset, count);
    batch_num++;

    btable[/*off + curindex[toff]*/curindex].sysnum = 40;
    btable[/*off + curindex[toff]*/curindex].rstatus = BENTRY_BUSY;
    btable[/*off + curindex[toff]*/curindex].nargs = 4;
    btable[/*off + curindex[toff]*/curindex].args[0] = outfd;
    btable[/*off + curindex[toff]*/curindex].args[1] = infd;
    btable[/*off + curindex[toff]*/curindex].args[2] = offset;
    btable[/*off + curindex[toff]*/curindex].args[3] = count;
    //curindex[toff] =
      //  (curindex[toff] == MAX_TABLE_SIZE - 1) ? 1 : curindex[toff] + 1;
    curindex = (curindex == MAX_TABLE_SIZE - 1) ? 1 : curindex + 1;
    /* assume always success */
    if(batch_num > 50)
            batch_flush();
    return count;
}
#if 1
ssize_t write(int fd, const void *buf, size_t count) {

    if (!in_segment) {
        real_write = real_write ? real_write : dlsym(RTLD_NEXT, "write");
        return real_write(fd, buf, count);
    }
    batch_num++;

    btable[curindex].sysnum = __NR_write;
    btable[curindex].rstatus = BENTRY_BUSY;
    btable[curindex].nargs = 3;
    btable[curindex].args[0] = fd;
    btable[curindex].args[1] = (long)buf;
    btable[curindex].args[2] = count;

    curindex = (curindex == MAX_TABLE_SIZE - 1) ? 1 : curindex + 1;
    if(batch_num > 50)
            batch_flush();
    return 0;
}
#endif


#include <fcntl.h>
#include <stdarg.h>
#define EXTRA_OPEN_FLAGS 0
#define AT_FDCWD -100

#if 0
int open64(const char *file, int oflag, ...)
{
    int mode = 0;
    if (__OPEN_NEEDS_MODE (oflag))
    {
        va_list arg;
        va_start (arg, oflag);
        mode = va_arg (arg, int);
        va_end (arg);
    }
    if (!in_segment) {
        return syscall (257, AT_FDCWD, file, oflag | EXTRA_OPEN_FLAGS,
                         mode);
    }
    batch_num++;

    btable[curindex].sysnum = 257;
    btable[curindex].rstatus = BENTRY_BUSY;
    btable[curindex].nargs = 4;
    btable[curindex].args[0] = AT_FDCWD;
    btable[curindex].args[1] = (long)file;
    btable[curindex].args[2] = oflag | EXTRA_OPEN_FLAGS;
    btable[curindex].args[3] = mode;

    curindex = (curindex == MAX_TABLE_SIZE - 1) ? 1 : curindex + 1;
    return 0;
}
#endif

#if 0
int __xstat64(int ver, const char *pname, struct stat* buf){
    if (!in_segment) {
        return syscall(4, pname, buf);
    }
    batch_num++;

    btable[curindex].sysnum = 4;
    btable[curindex].rstatus = BENTRY_BUSY;
    btable[curindex].nargs = 2;
    btable[curindex].args[0] = pname;
    btable[curindex].args[1] = (long)buf;

    curindex = (curindex == MAX_TABLE_SIZE - 1) ? 1 : curindex + 1;
    return 0;

}
#endif 

#if 1
int __fxstat64(int ver, int fd,  struct stat64 *buf) {
    if (!in_segment) {
	//printf("----------\n");
   	//printf("%ld %d %ld %ld %ld %ld %ld\n", buf->st_ino, buf->st_mode, buf->st_nlink, buf->st_rdev, buf->st_size, buf->st_blksize, buf->st_blocks);
        syscall(5, fd, buf);
	//printf("%ld %d %ld %ld %ld %ld %ld\n", buf->st_ino, buf->st_mode, buf->st_nlink, buf->st_rdev, buf->st_size, buf->st_blksize, buf->st_blocks);

	return 0;
    }
    buf->st_ino = 7996678;
    buf->st_mode = 33204;
    buf->st_nlink = 1;
    buf->st_rdev = 0;
    buf->st_size = 920;
    buf->st_blksize = 4096;
    buf->st_blocks = 8;
    return 0;
#if 0
    batch_num++;

    btable[curindex].sysnum = 5;
    btable[curindex].rstatus = BENTRY_BUSY;
    btable[curindex].nargs = 2;
    btable[curindex].args[0] = fd;
    btable[curindex].args[1] = (long)buf;

    curindex = (curindex == MAX_TABLE_SIZE - 1) ? 1 : curindex + 1;
    return 0;
#endif
}
#endif

#if 1
#define MAX_POOL_IOV_SIZE 100

/*
struct iovec{
	void* iov_base;
	size_t iov_len;
};*/
struct iovec *iovpool;
int iov_offset;


ssize_t writev(int fd, const struct iovec *iov, int iovcnt) {
    if (!in_segment) {
        return syscall(20, fd, iov, iovcnt);
    }
    batch_num++;

    int len = 0, i;

    for(i = 0; i < iovcnt; i++){
        int ll = iov[i].iov_len;
        /* handle string */
        if (pool_offset + (ll / POOL_UNIT) > MAX_POOL_SIZE)
            pool_offset = 0;
        else
            pool_offset += (ll / POOL_UNIT);

        /* handle iovec */
        if (iov_offset + 1 >= MAX_POOL_IOV_SIZE)
            iov_offset = 0;
        else
            iov_offset++;
        memcpy(mpool + pool_offset, iov[i].iov_base, ll);

        iovpool[iov_offset].iov_base = mpool + pool_offset;
        iovpool[iov_offset].iov_len = ll;
        len += iov[i].iov_len;
    }

    btable[curindex].sysnum = 20;
    btable[curindex].rstatus = BENTRY_BUSY;
    btable[curindex].nargs = 3;
    btable[curindex].args[0] = fd;
    btable[curindex].args[1] = (long)(iovpool + iov_offset - iovcnt + 1);
    btable[curindex].args[2] = iovcnt;

    curindex = (curindex == MAX_TABLE_SIZE - 1) ? 1 : curindex + 1;
    /* assume always success */
    return len;
}
#endif

#if 0
#include <sched.h>
int epoll_wait(int epfd, struct epoll_event *events, 
		int maxevent, int timeout)
{
   //real_ep_w = real_ep_w ? real_ep_w : dlsym(RTLD_NEXT, "epoll_wait");
    /*while(1){
	//printf("vd_avail = %d\n", fastpoll());
	if(fastpoll() != 0){
	//	printf("vd_avail = %d\n", fastpoll());
		break;
	}
	sched_yield();
    }*/

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

    iovpool = (struct iovec*)malloc(sizeof(struct iovec) * MAX_POOL_IOV_SIZE);
    iov_offset = 0;

    /* get pid of main thread */
    main_thread_pid = syscall(186);

    //btable =
      //  (struct batch_entry *)aligned_alloc(pgsize, pgsize * MAX_THREAD_NUM);

    //syscall(__NR_register, btable);
    //signal(SIGINT, ctrl_c_hdlr);

    //for (i = 0; i < MAX_THREAD_NUM; i++)
      //  curindex[i] = 1;
}
