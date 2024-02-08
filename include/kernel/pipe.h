#include <kernel/types.h>
#include <kernel/synch.h>
#include <kernel/pmem.h>
#include <kernel/bdev.h>
#include <kernel/list.h>
#include <kernel/radix_tree.h>
#include <kernel/synch.h>

#define BUFFER_SIZE 512

struct BBQ {
    struct condvar cv_read;
    struct condvar cv_write;
    int front;
    int next_empty;
    char data[BUFFER_SIZE];
};

struct pipe {
    struct BBQ *buffer; 
    struct file *read;
    struct file *write;
};

struct pipe *pipe_alloc();

struct BBQ *BBQ_alloc();

// static ssize_t pipe_read(struct file *file, void *buf, size_t count, offset_t *ofs);
// static ssize_t pipe_write(struct file *file, const void *buf, size_t count, offset_t *ofs);
// static void pipe_close(struct file *p);

