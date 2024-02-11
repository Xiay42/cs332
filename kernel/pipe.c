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

// define pipe-op functions
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

    // allocate space for pipe and bbq, set up bbq 
    pipe *pipe = kmalloc(sizeof(pipe));
    pipe->q = bbq_init();

    // allocate and set up read-file
    struct file *read_file = fs_alloc_file();
    if (read_file == NULL) {
        return NULL;
    }
    read_file->f_ops = &pipe_ops;
    read_file->oflag = FS_RDONLY;
    read_file->info = pipe;
    pipe->read = read_file;
    
    // allocate and set up write_file
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

    // check that the write end is only used for writing
    if (file->oflag == FS_RDONLY) {
        return -1;
    }

    pipe *pipe = file->info;
    int chars_written = 0;

    // loop through the buffer and read one char at a time
    while (chars_written < count) {
        // check is the read end is closed
        if (pipe->read == NULL) {
            return ERR_END;
        }
        // put the char into bbq
        bbq_insert(pipe->q, ((char *)buf)[chars_written]);
        chars_written++;
    }

    return chars_written;
}

ssize_t pipe_read(struct file *file, void *buf, size_t count, offset_t *ofs) {

    // check that the read end is only used for reading
    if (file->oflag == FS_WRONLY) {
        return -1;
    }

    pipe *pipe = file->info;
    int chars_read = 0;

    // loop through the buffer and read one char at a time
    while (chars_read < count){
        // check if the write end is closed & there's nothing to read.
        if (pipe->write == NULL && pipe->q->front == pipe->q->next_empty) {
            return chars_read;
        }
        // read char & remove from bbq
        ((char *)buf)[chars_read] = bbq_remove(pipe->q);
        chars_read++;
    }
    
    return chars_read;
}

void pipe_close(struct file *p) {
    // check which end of the pipe we want to close
    if (p->oflag != FS_WRONLY) {
        // close the read end of the pipe
        ((pipe *)p->info)->read = NULL;
    } else {
        // close the write end of the pipe
        ((pipe *)p->info)->write = NULL;
    }
    return;
}
