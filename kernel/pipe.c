#include <kernel/pipe.h>
#include <kernel/fs.h>
#include <lib/errcode.h>
#include <kernel/synch.h>
#include <kernel/bbq.h>
#include <kernel/proc.h>
#include <kernel/thread.h>
#include <kernel/console.h>
#include <kernel/kmalloc.h>
#include <lib/syscall-num.h>
#include <lib/stddef.h>
#include <lib/string.h>
#include <arch/asm.h>

static ssize_t pipe_read(struct file *file, void *buf, size_t count, offset_t *ofs);
static ssize_t pipe_write(struct file *file, const void *buf, size_t count, offset_t *ofs);
static void pipe_close(struct file *p);

static struct file_operations pipe_ops = {
    .read = pipe_read,
    .write = pipe_write,
    .close = pipe_close,
    .readdir = fs_readdir
};


pipe *pipe_alloc() {
    pipe *pipe = kmalloc(sizeof(pipe));

    pipe->q = bbq_init();

    struct file *read_file = fs_alloc_file();
    if (read_file == NULL) {
        return NULL;
    }
    read_file->f_ops = &pipe_ops;
    read_file->oflag = FS_RDONLY;
    read_file->info = pipe;
    pipe->read = read_file;
    
    struct file *write_file = fs_alloc_file();
    if (write_file == NULL) {
        return NULL;
    }
    write_file->f_ops = &pipe_ops;
    write_file->oflag = FS_WRONLY;
    write_file->info = pipe;
    pipe->write = write_file;

    return pipe;
}

ssize_t pipe_write(struct file *file, const void *buf, size_t count, offset_t *ofs) {

    if (file->oflag == FS_RDONLY) {
        return -1;
    }

    pipe *pipe = file->info;

    // input validation

    bbq_insert(pipe->q, *(char *)buf);

    return count;
}

ssize_t pipe_read(struct file *file, void *buf, size_t count, offset_t *ofs) {

    
    if (file->oflag == FS_WRONLY) {
        return -1;
    }

    pipe *pipe = file->info;
    char item = bbq_remove(pipe->q);
    *(char *)buf = item;
    
    return count;
}

void pipe_close(struct file *p) {
    if (p->oflag != FS_WRONLY) {
        ((pipe *)p->info)->read = NULL;
    } else {
        ((pipe *)p->info)->write = NULL;
    }
    return;
}
