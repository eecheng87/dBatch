#define _GNU_SOURCE

#define DYNAMIC_PRE_ENABLE 1

#define MAX_TABLE_SIZE 64
#define MAX_THREAD_NUM 10
#define MAX_POOL_SIZE 130172
#define POOL_UNIT 8
#define BATCH_THRESHOLD 6

#define PREDICT_S1 1
#define PREDICT_S2 2
#define PREDICT_S3 3
#define PREDICT_S4 4

#include "../include/linux/batch.h"
#include <dlfcn.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

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
