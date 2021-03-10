#include "preload.h"
int curindex[MAX_THREAD_NUM];
int table_size = 64;
int main_thread_pid;
int in_segment;
void *mpool; /* memory pool */
int pool_offset;
struct iovec *iovpool; /* pool for iovector */
int iov_offset;
int batch_num;   /* number of busy entry */
int syscall_num; /* number of syscall triggered currently */
int predict_res; /* 1: do batch; 0: do normal */
int predict_state;

void get_next_state(int tran) {
#if DEBUG
    printf("In state %d, sysnum is %d\n", predict_state, tran);
#endif
    switch (predict_state) {
    case PREDICT_S1:
        predict_state = (tran > BATCH_THRESHOLD) ? PREDICT_S2 : PREDICT_S1;
        predict_res = 0;
        break;
    case PREDICT_S2:
        predict_state = (tran > BATCH_THRESHOLD) ? PREDICT_S3 : PREDICT_S1;
        predict_res = 0;
        break;
    case PREDICT_S3:
        predict_state = (tran > BATCH_THRESHOLD) ? PREDICT_S4 : PREDICT_S2;
        predict_res = 1;
        break;
    default:
        /* S4 */
        predict_state = (tran > BATCH_THRESHOLD) ? PREDICT_S4 : PREDICT_S3;
        predict_res = 1;
        break;
    }
    syscall_num = 0;
}

long batch_start() {
    in_segment = 1;
    batch_num = 0;
    return 0;
}

long batch_flush() {
    in_segment = 0;

/* avoid useless batch_flush */
#if DYNAMIC_PRE_ENABLE
    get_next_state(syscall_num);
#endif
    if (batch_num == 0)
        return 0;
    return syscall(__NR_batch_flush);
}

#if 0
int open(const char *pathname, int flags, mode_t mode) {

    syscall_num++;
    if (!in_segment || !predict_res) {
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

int close(int fd) {

    syscall_num++;
    if (!in_segment || !predict_res) {
        return real_close(fd);
    }
    batch_num++;

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

    syscall_num++;
    if (!in_segment || !predict_res) {
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

    syscall_num++;
    if (!in_segment || !predict_res) {
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

    if (!in_segment || !predict_res) {
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
#endif
#if 0
int close(int fd) {

    syscall_num++;
    if (!in_segment || !predict_res) {
        return real_close(fd);
    }
    batch_num++;

    int off, toff = 0, len = 0, i;
    off = curindex[1] << 6; /* 6 = log64 */

    btable[off + curindex[toff]].sysnum = __NR_close;
    btable[off + curindex[toff]].rstatus = BENTRY_BUSY;
    btable[off + curindex[toff]].nargs = 1;
    btable[off + curindex[toff]].args[0] = fd;
    btable[off + curindex[toff]].pid = main_thread_pid + off;
    if (curindex[toff] == MAX_TABLE_SIZE - 1) {
        if (curindex[1] == MAX_THREAD_NUM - 1) {
            curindex[1] = 1;
        } else {
            curindex[1]++;
        }
        curindex[toff] = 1;
    } else {
        curindex[toff]++;
    }
    return 0;
}
#endif

ssize_t shutdown(int fd, int how) {

    syscall_num++;
    if (!in_segment || !predict_res) {
        return real_shutdown(fd, how);
    }
    batch_num++;

    int off, toff = 0;
    off = curindex[1] << 6; /* 6 = log64 */

    btable[off + curindex[toff]].sysnum = __NR_shutdown;
    btable[off + curindex[toff]].rstatus = BENTRY_BUSY;
    btable[off + curindex[toff]].nargs = 2;
    btable[off + curindex[toff]].args[0] = fd;
    btable[off + curindex[toff]].args[1] = how;
    btable[off + curindex[toff]].pid = main_thread_pid + off;

    if (curindex[toff] == MAX_TABLE_SIZE - 1) {
        if (curindex[1] == MAX_THREAD_NUM - 1) {
            curindex[1] = 1;
        } else {
            curindex[1]++;
        }
        curindex[toff] = 1;
    } else {
        curindex[toff]++;
    }

    /* assume success */
    return 0;
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt) {
    syscall_num++;
    if (!in_segment || !predict_res) {
        return real_writev(fd, iov, iovcnt);
    }
    batch_num++;

    int off, toff = 0, len = 0, i;
    off = curindex[1] << 6; /* 6 = log64 */

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

    btable[off + curindex[toff]].sysnum = __NR_writev;
    btable[off + curindex[toff]].rstatus = BENTRY_BUSY;
    btable[off + curindex[toff]].nargs = 3;
    btable[off + curindex[toff]].args[0] = fd;
    btable[off + curindex[toff]].args[1] = (long)(iovpool + iov_offset - iovcnt + 1);
    btable[off + curindex[toff]].args[2] = iovcnt;
    btable[off + curindex[toff]].pid = main_thread_pid + off;

    if (curindex[toff] == MAX_TABLE_SIZE - 1) {
        if (curindex[1] == MAX_THREAD_NUM - 1) {
            curindex[1] = 1;
        } else {
            curindex[1]++;
        }
        curindex[toff] = 1;
    } else {
        curindex[toff]++;
    }
    /* assume always success */
    //printf("-> %d\n", len);
    return len;

}

ssize_t sendto(int sockfd, void *buf, size_t len, unsigned flags,
               struct sockaddr *dest_addr, int addrlen) {

    syscall_num++;
    if (!in_segment || !predict_res) {
        return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
    }
    batch_num++;

    int off, toff = 0;
    off = curindex[1] << 6; /* 6 = log64 */

    if (pool_offset + (len / POOL_UNIT) > MAX_POOL_SIZE)
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

    if (curindex[toff] == MAX_TABLE_SIZE - 1) {
        if (curindex[1] == MAX_THREAD_NUM - 1) {
            curindex[1] = 1;
        } else {
            curindex[1]++;
        }
        curindex[toff] = 1;
    } else {
        curindex[toff]++;
    }
    /* assume always success */
    return len;
}

ssize_t send(int sockfd, void *buf, size_t len, unsigned flags,
             struct sockaddr *dest_addr, int addrlen) {
    sendto(sockfd, buf, len, flags, NULL, 0);
}

__attribute__((constructor)) static void setup(void) {
    int i;
    size_t pgsize = getpagesize();
    in_segment = 0;
    batch_num = 0;
    syscall_num = 0;
    predict_state = PREDICT_S1;
#if DYNAMIC_PRE_ENABLE
    predict_res = 0;
#else
    predict_res = 1;
#endif
    /* init memory pool */
    mpool = (void *)malloc(sizeof(unsigned char) * MAX_POOL_SIZE);
    pool_offset = 0;

    iovpool = (struct iovec*)malloc(sizeof(struct iovec) * MAX_POOL_IOV_SIZE);
    iov_offset = 0;

    /* get pid of main thread */
    main_thread_pid = syscall(186);
    btable =
        (struct batch_entry *)aligned_alloc(pgsize, pgsize * MAX_THREAD_NUM);

    /* store glibc function */
    real_open = real_open ? real_open : dlsym(RTLD_NEXT, "open");
    real_close = real_close ? real_close : dlsym(RTLD_NEXT, "close");
    real_write = real_write ? real_write : dlsym(RTLD_NEXT, "write");
    real_read = real_read ? real_read : dlsym(RTLD_NEXT, "read");
    real_sendto = real_sendto ? real_sendto : dlsym(RTLD_NEXT, "sendto");
    real_writev = real_writev ? real_writev : dlsym(RTLD_NEXT, "writev");
    real_shutdown = real_shutdown ? real_shutdown : dlsym(RTLD_NEXT, "shutdown");

    syscall(__NR_register, btable);

    for (i = 0; i < MAX_THREAD_NUM; i++)
        curindex[i] = 1;
}