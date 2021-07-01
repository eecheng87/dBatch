#include "preload.h"
int curindex[MAX_THREAD_NUM];
int table_size = 64;
int main_thread_pid;
int in_segment;
void *mpool; /* memory pool */
int pool_offset;
int batch_num; /* number of busy entry */

long batch_start() {
    in_segment = 1;
    if(!btable){
    int pgsize = getpagesize();
    btable =
        (struct batch_entry *)aligned_alloc(pgsize, pgsize * MAX_THREAD_NUM);

    syscall(__NR_register, btable);
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
    return syscall(__NR_batch_flush);
}
#if 0
int open(const char *pathname, int flags, mode_t mode) {

    if (!in_segment) {
        real_open = real_open ? real_open : dlsym(RTLD_NEXT, "open");
        return real_open(pathname, flags, mode);
    }
    batch_num++;

    int off,
        toff = (((struct pthread_fake *)pthread_self())->tid - main_thread_pid);
    off = toff << 6; /* 6 = log64 */
    btable[off + curindex[toff]].sysnum = __NR_open;
    btable[off + curindex[toff]].rstatus = BENTRY_BUSY;
    btable[off + curindex[toff]].nargs = 3;
    btable[off + curindex[toff]].args[0] = (long)pathname;
    btable[off + curindex[toff]].args[1] = flags;
    btable[off + curindex[toff]].args[2] = mode;
    btable[off + curindex[toff]].pid = main_thread_pid + off;
    curindex[toff] =
        (curindex[toff] == MAX_TABLE_SIZE - 1) ? 1 : curindex[toff] + 1;

    /* memorize the -index of fd */
    return -(curindex[toff] - 1);
}
#endif

int close(int fd) {

    if (!in_segment) {
        real_close = real_close ? real_close : dlsym(RTLD_NEXT, "close");
        return real_close(fd);
    }
    batch_num++;

    int off,
        toff = (((struct pthread_fake *)pthread_self())->tid - main_thread_pid);
    off = toff << 6; /* 6 = log64 */
    off = 0;
    btable[off + curindex[toff]].sysnum = __NR_close;
    btable[off + curindex[toff]].rstatus = BENTRY_BUSY;
    btable[off + curindex[toff]].nargs = 1;
    btable[off + curindex[toff]].args[0] = fd;
    btable[off + curindex[toff]].pid = main_thread_pid + off;
    curindex[toff] =
        (curindex[toff] == MAX_TABLE_SIZE - 1) ? 1 : curindex[toff] + 1;

    return 0;
}

#if 0
ssize_t write(int fd, const void *buf, size_t count) {

    if (!in_segment) {
        real_write = real_write ? real_write : dlsym(RTLD_NEXT, "write");
        return real_write(fd, buf, count);
    }
    batch_num++;

    int off,
        toff = (((struct pthread_fake *)pthread_self())->tid - main_thread_pid);
    off = toff << 6; /* 6 = log64 */
    btable[off + curindex[toff]].sysnum = __NR_write;
    btable[off + curindex[toff]].rstatus = BENTRY_BUSY;
    btable[off + curindex[toff]].nargs = 3;
    btable[off + curindex[toff]].args[0] = fd;
    btable[off + curindex[toff]].args[1] = (long)buf;
    btable[off + curindex[toff]].args[2] = count;
    btable[off + curindex[toff]].pid = main_thread_pid + off;

    curindex[toff] =
        (curindex[toff] == MAX_TABLE_SIZE - 1) ? 1 : curindex[toff] + 1;

    return 0;
}

ssize_t read(int fd, void *buf, size_t count) {

    if (!in_segment) {
        real_read = real_read ? real_read : dlsym(RTLD_NEXT, "read");
        return real_read(fd, buf, count);
    }
    batch_num++;

    int off,
        toff = (((struct pthread_fake *)pthread_self())->tid - main_thread_pid);
    off = toff << 6; /* 6 = log64 */
    btable[off + curindex[toff]].sysnum = __NR_read;
    btable[off + curindex[toff]].rstatus = BENTRY_BUSY;
    btable[off + curindex[toff]].nargs = 3;
    btable[off + curindex[toff]].args[0] = fd;
    btable[off + curindex[toff]].args[1] = (long)buf;
    btable[off + curindex[toff]].args[2] = count;
    btable[off + curindex[toff]].pid = main_thread_pid + off;
    curindex[toff] =
        (curindex[toff] == MAX_TABLE_SIZE - 1) ? 1 : curindex[toff] + 1;

    return 0;
}

ssize_t sendto(int sockfd, void *buf, size_t len, unsigned flags,
               struct sockaddr *dest_addr, int addrlen) {

    if (!in_segment) {
        real_sendto = real_sendto ? real_sendto : dlsym(RTLD_NEXT, "sendto");
        return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
    }
    batch_num++;

    int off,
        toff = (((struct pthread_fake *)pthread_self())->tid - main_thread_pid);
    off = toff << 6; /* 6 = log64 */

    if(pool_offset + (len / POOL_UNIT) >= MAX_POOL_SIZE)
        pool_offset = 0;
    else
        pool_offset += (len / POOL_UNIT);
    memcpy(mpool + pool_offset, buf, len);

    btable[off + curindex[toff]].sysnum = __NR_sendto;
    btable[off + curindex[toff]].rstatus = BENTRY_BUSY;
    btable[off + curindex[toff]].nargs = 6;
    btable[off + curindex[toff]].args[0] = sockfd;
    btable[off + curindex[toff]].args[1] = (long)(mpool + pool_offset);
    btable[off + curindex[toff]].args[2] = len;
    btable[off + curindex[toff]].args[3] = flags;
    btable[off + curindex[toff]].args[4] = (long)dest_addr;
    btable[off + curindex[toff]].args[5] = addrlen;
    btable[off + curindex[toff]].pid = main_thread_pid + off;
    curindex[toff] =
        (curindex[toff] == MAX_TABLE_SIZE - 1) ? 1 : curindex[toff] + 1;

    /* assume always success */
    return len;
}

ssize_t send(int sockfd, void *buf, size_t len, unsigned flags,
               struct sockaddr *dest_addr, int addrlen) {
    sendto(sockfd, buf, len, flags, NULL, 0);
}
#endif

ssize_t sendfile64(int outfd, int infd, off_t* offset, size_t count){
    //printf("-> sendfile(%d,%d,%ld,%ld)\n", outfd, infd, offset, count);
    //real_sendfile = dlsym(RTLD_NEXT, "sendfile");
    if (!in_segment) {
        real_sendfile = real_sendfile ? real_sendfile : dlsym(RTLD_NEXT, "sendfile64");
        return real_sendfile(outfd, infd ,offset, count);
    }
    //return real_sendfile(outfd, infd, offset, count);
    batch_num++;

    int off,
        toff = (((struct pthread_fake *)pthread_self())->tid - main_thread_pid);
    off = toff << 6; /* 6 = log64 */
//printf("fill index %d\n", off + curindex[toff]);
    off = 0;
    btable[off + curindex[toff]].sysnum = 40;
    btable[off + curindex[toff]].rstatus = BENTRY_BUSY;
    btable[off + curindex[toff]].nargs = 4;
    btable[off + curindex[toff]].args[0] = outfd;
    btable[off + curindex[toff]].args[1] = infd;
    btable[off + curindex[toff]].args[2] = offset;
    btable[off + curindex[toff]].args[3] = count;
    btable[off + curindex[toff]].pid = main_thread_pid + off;
    curindex[toff] =
        (curindex[toff] == MAX_TABLE_SIZE - 1) ? 1 : curindex[toff] + 1;

    /* assume always success */
    return count;
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
//    btable =
//        (struct batch_entry *)aligned_alloc(pgsize, pgsize * MAX_THREAD_NUM);

//    syscall(__NR_register, btable);
    for (i = 0; i < MAX_THREAD_NUM; i++)
        curindex[i] = 1;
}
