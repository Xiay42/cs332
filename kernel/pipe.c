#include <kernel/pipe.h>
#include <kernel/fs.h>
#include <lib/errcode.h>

struct BBQ *BBQ_alloc() {
    struct BBQ *buffer = kmalloc(sizeof(struct BBQ));

    struct condvar cv_read;
    condvar_init(&cv_read);
    buffer->cv_read = cv_read;

    struct condvar cv_write;
    condvar_init(&cv_write);
    buffer->cv_write = cv_write;

    return buffer;
}


struct pipe *pipe_alloc() {
    struct pipe *pipe = kmalloc(sizeof(struct pipe));

    pipe->buffer = BBQ_alloc();

    struct file *read_file = fs_alloc_file();
    if (read_file == NULL) {
        return NULL;
    }
    pipe->read = read_file;

    struct file *write_file = fs_alloc_file();
    if (write_file == NULL) {
        return NULL;
    }
    pipe->write = write_file;

    return pipe;
}


// ssize_t pipe_write(struct file *file, const void *buf, size_t count, offset_t *ofs) {
//     return NULL;
// }
// ssize_t pipe_read(struct file *file, void *buf, size_t count, offset_t *ofs) {
//     return NULL;
// }
// void pipe_close(struct file *p) {
//     return;
// }
