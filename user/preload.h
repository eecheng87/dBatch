#define _GNU_SOURCE

#define MAX_TABLE_SIZE 64
#define MAX_THREAD_NUM 10
#define MAX_POOL_SIZE 130172
#define POOL_UNIT 8
#define u32 unsigned int
#define s32 signed int
#define u64 unsigned long

#include <dlfcn.h>
#include <inttypes.h>
#include "../include/linux/batch.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/auxv.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <signal.h>

struct pthread_fake {
    /* offset to find tid */
    void *nothing[90];
    pid_t tid;
};

struct batch_entry *btable;
extern int curindex[MAX_THREAD_NUM];

typedef long (*open_t)(const char *pathname, int flags, mode_t mode);
open_t real_open;
typedef long (*read_t)(int fd, void *buf, size_t count);
read_t real_read;
typedef long (*write_t)(unsigned int fd, const char *buf, size_t count);
write_t real_write;
typedef long (*close_t)(int fd);
close_t real_close;
typedef long (*sendto_t)(int sockfd, void *buf, size_t len, unsigned flags,
               struct sockaddr *dest_addr, int addrlen);
sendto_t real_sendto;
typedef long (*sendfile_t)(int outfd, int infd, off_t* offset, size_t count);
sendfile_t real_sendfile;
typedef long (*epoll_wait_t)(int, struct epoll_event*, int, int);
epoll_wait_t real_ep_w;