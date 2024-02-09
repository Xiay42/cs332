#include <kernel/types.h>
#include <kernel/synch.h>
#include <kernel/pmem.h>
#include <kernel/bdev.h>
#include <kernel/list.h>
#include <kernel/radix_tree.h>
#include <kernel/synch.h>
#include <kernel/fs.h>
#include <kernel/bbq.h>

#ifndef __PIPE_H__
#define __PIPE_H__

typedef struct {
    BBQ *q;
    struct file *read;
    struct file *write;
}pipe;

pipe *pipe_alloc();

#endif // __PIPE_H__