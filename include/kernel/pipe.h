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
    BBQ *q;             // pipe's BBQ
    struct file *read;  // read end of pipe
    struct file *write; // write end of pipe
}pipe;

// allocate space for pipe and set up its data structures
pipe *pipe_alloc();

#endif // __PIPE_H__