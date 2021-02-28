#include "preload.h"
int curindex[MAX_THREAD_NUM];
int table_size = 64;
int main_thread_pid;
int in_segment;

long batch_start(){
    in_segment = 1;
    return 0;
}

long batch_flush(){
    in_segment = 0;
    return syscall(__NR_batch_flush);
}

int open(const char *pathname, int flags, mode_t mode) {

    if(!in_segment){
        real_open = real_open ? real_open : dlsym(RTLD_NEXT, "open");
        return real_open(pathname, flags, mode);
    }

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

int close(int fd) {

    if(!in_segment){
        real_close = real_close ? real_close : dlsym(RTLD_NEXT, "close");
        return real_close(fd);
    }

    int off,
        toff = (((struct pthread_fake *)pthread_self())->tid - main_thread_pid);
    off = toff << 6; /* 6 = log64 */
    btable[off + curindex[toff]].sysnum = __NR_close;
    btable[off + curindex[toff]].rstatus = BENTRY_BUSY;
    btable[off + curindex[toff]].nargs = 1;
    btable[off + curindex[toff]].args[0] = fd;
    btable[off + curindex[toff]].pid = main_thread_pid + off;
    curindex[toff] =
        (curindex[toff] == MAX_TABLE_SIZE - 1) ? 1 : curindex[toff] + 1;

    return 0;
}

ssize_t write(int fd, const void *buf, size_t count) {

    if(!in_segment){
        real_write = real_write ? real_write : dlsym(RTLD_NEXT, "write");
        return real_write(fd, buf, count);
    }

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

    if(!in_segment){
        real_read = real_read ? real_read : dlsym(RTLD_NEXT, "read");
        return real_read(fd, buf, count);
    }

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

__attribute__((constructor)) static void setup(void) {
    int i;
    size_t pgsize = getpagesize();
    in_segment = 0;

    /* get pid of main thread */
    main_thread_pid = syscall(186);
    btable =
        (struct batch_entry *)aligned_alloc(pgsize, pgsize * MAX_THREAD_NUM);
    syscall(__NR_register, btable);
    for (i = 0; i < MAX_THREAD_NUM; i++)
        curindex[i] = 1;
}