#include <kernel/proc.h>
#include <kernel/thread.h>
#include <kernel/console.h>
#include <kernel/kmalloc.h>
#include <kernel/fs.h>
#include <lib/syscall-num.h>
#include <lib/errcode.h>
#include <lib/stddef.h>
#include <lib/string.h>
#include <arch/asm.h>
#include <kernel/pipe.h>


// syscall handlers
static sysret_t sys_fork(void* arg);
static sysret_t sys_spawn(void* arg);
static sysret_t sys_wait(void* arg);
static sysret_t sys_exit(void* arg);
static sysret_t sys_getpid(void* arg);
static sysret_t sys_sleep(void* arg);
static sysret_t sys_open(void* arg);
static sysret_t sys_close(void* arg);
static sysret_t sys_read(void* arg);
static sysret_t sys_write(void* arg);
static sysret_t sys_link(void* arg);
static sysret_t sys_unlink(void* arg);
static sysret_t sys_mkdir(void* arg);
static sysret_t sys_chdir(void* arg);
static sysret_t sys_readdir(void* arg);
static sysret_t sys_rmdir(void* arg);
static sysret_t sys_fstat(void* arg);
static sysret_t sys_sbrk(void* arg);
static sysret_t sys_meminfo(void* arg);
static sysret_t sys_dup(void* arg);
static sysret_t sys_pipe(void* arg);
static sysret_t sys_info(void* arg);
static sysret_t sys_halt(void* arg);

extern size_t user_pgfault;
struct sys_info {
    size_t num_pgfault;
};

/*
 * Machine dependent syscall implementation: fetches the nth syscall argument.
 */
extern bool fetch_arg(void *arg, int n, sysarg_t *ret);

/*
 * Validate string passed by user.
 */
static bool validate_str(char *s);
/*
 * Validate buffer passed by user.
 */
static bool validate_ptr(void* ptr, size_t size);


static sysret_t (*syscalls[])(void*) = {
    [SYS_fork] = sys_fork,
    [SYS_spawn] = sys_spawn,
    [SYS_wait] = sys_wait,
    [SYS_exit] = sys_exit,
    [SYS_getpid] = sys_getpid,
    [SYS_sleep] = sys_sleep,
    [SYS_open] = sys_open,
    [SYS_close] = sys_close,
    [SYS_read] = sys_read,
    [SYS_write] = sys_write,
    [SYS_link] = sys_link,
    [SYS_unlink] = sys_unlink,
    [SYS_mkdir] = sys_mkdir,
    [SYS_chdir] = sys_chdir,
    [SYS_readdir] = sys_readdir,
    [SYS_rmdir] = sys_rmdir,
    [SYS_fstat] = sys_fstat,
    [SYS_sbrk] = sys_sbrk,
    [SYS_meminfo] = sys_meminfo,
    [SYS_dup] = sys_dup,
    [SYS_pipe] = sys_pipe,
    [SYS_info] = sys_info,
    [SYS_halt] = sys_halt,
};

static int
alloc_fd(struct file *f)
{
    // get the current thread's process
    struct proc *p = proc_current();
    kassert(p);

    // check for the first empty file descriptor
    int fd = 0;    
    while (p->fd_table[fd] != NULL && fd < PROC_MAX_FILE) {
        fd++;
    }

    // if the fd table is full, return an error
    if (fd == PROC_MAX_FILE) {
        return ERR_NOMEM;
    }
    
    // save the file into the file descriptor table and return its index
    p->fd_table[fd] = f;
    return fd;
}

static bool
validate_fd(int fd)
{
    // get the current thread's process
    struct proc *p = proc_current();
    kassert(p);

    // make sure fd is within the valid range
    if ((fd < 0) || (fd > PROC_MAX_FILE - 1)) {
        return False;
    }
    
    // return if the fd is in the open file table for the current process
    return (p->fd_table[fd] != NULL);
}

static bool
validate_str(char *s)
{
    struct memregion *mr;
    // find given string's memory region
    if((mr = as_find_memregion(&proc_current()->as, (vaddr_t) s, 1)) == NULL) {
        return False;
    }
    // check in case the string keeps growing past user specified amount
    for(; s < (char*) mr->end; s++){
        if(*s == 0) {
            return True;
        }
    }
    return False;
}

static bool
validate_ptr(void* ptr, size_t size)
{
    vaddr_t ptraddr = (vaddr_t) ptr;
    if (ptraddr + size < ptraddr) {
        return False;
    }
    // verify argument ptr points to a valid chunk of memory of size bytes
    return as_find_memregion(&proc_current()->as, ptraddr, size) != NULL;
}


// int fork(void);
static sysret_t
sys_fork(void *arg)
{
    struct proc *p;
    if ((p = proc_fork()) == NULL) {
        return ERR_NOMEM;
    }
    return p->pid;
}

// int spawn(const char *args);
static sysret_t
sys_spawn(void *arg)
{
    int argc = 0;
    sysarg_t args;
    size_t len;
    char *token, *buf, **argv;
    struct proc *p;
    err_t err;

    // argument fetching and validating
    kassert(fetch_arg(arg, 1, &args));
    if (!validate_str((char*)args)) {
        return ERR_FAULT;
    }

    len = strlen((char*)args) + 1;
    if ((buf = kmalloc(len)) == NULL) {
        return ERR_NOMEM;
    }
    // make a copy of the string to not modify user data
    memcpy(buf, (void*)args, len);
    // figure out max number of arguments possible
    len = len / 2 < PROC_MAX_ARG ? len/2 : PROC_MAX_ARG;
    if ((argv = kmalloc((len+1)*sizeof(char*))) == NULL) {
        kfree(buf);
        return ERR_NOMEM;
    }
    // parse arguments  
    while ((token = strtok_r(NULL, " ", &buf)) != NULL) {
        argv[argc] = token;
        argc++;
    }
    argv[argc] = NULL;

    if ((err = proc_spawn(argv[0], argv, &p)) != ERR_OK) {
        return err;
    }
    return p->pid;
}

// int wait(int pid, int *wstatus);
static sysret_t
sys_wait(void* arg)
{
    // fetch args
    sysarg_t pid_arg;
    sysarg_t wstatus_arg;
    kassert(fetch_arg(arg, 1, &pid_arg));
    kassert(fetch_arg(arg, 2, &wstatus_arg));
    
    // convert arguments to their proper types
    int pid = (int)pid_arg;
    int *wstatus = (int *)wstatus_arg;

    // make sure pid is valid
    if (pid < -1) {
        return ERR_CHILD;
    }

    // validate wstatus
    if (wstatus != NULL) {
        if (!validate_ptr(wstatus, sizeof(int))) {
            return ERR_FAULT;
        }
    }    

    int return_pid = proc_wait(pid, wstatus);
    
    return return_pid;
}

// void exit(int status);
static sysret_t
sys_exit(void* arg)
{
    // fetch args
    sysarg_t status_arg;
    kassert(fetch_arg(arg, 1, &status_arg));
    
    // Convert arguments to their proper types
    int status = (int)status_arg;
    
    proc_exit(status);
    
    panic("oops still running");
}

// int getpid(void);
static sysret_t
sys_getpid(void* arg)
{
    return proc_current()->pid;
}

// void sleep(unsigned int, seconds);
static sysret_t
sys_sleep(void* arg)
{
    panic("syscall sleep not implemented");
}

// int open(const char *pathname, int flags, fmode_t mode);
static sysret_t
sys_open(void *arg)
{
    // fetch args
    sysarg_t pathname_arg, flags_arg, mode_arg;
    kassert(fetch_arg(arg, 1, &pathname_arg));
    kassert(fetch_arg(arg, 2, &flags_arg));
    kassert(fetch_arg(arg, 3, &mode_arg));

    // convert arguments to their proper types
    char *pathname = (char *)pathname_arg;
    int flags = (int)flags_arg;
    fmode_t mode = (fmode_t)mode_arg;

    // validate the address of the pathname
    if (!validate_str((char*)pathname)) {
        return ERR_FAULT;
    }

    // open the file 
    struct file *file;
    struct proc *p = proc_current();
    kassert(p);
    err_t res = fs_open_file(pathname, flags, mode, &file);

    // if fs_open_file() has an error, return it
    if (res != ERR_OK) {
        return res;
    }
    
    // add file to the fd_table and return its index
    int fd = alloc_fd(file);
    return (sysret_t) fd;
}

// int close(int fd);
static sysret_t
sys_close(void *arg)
{
    // fetch arg
    sysarg_t fd_arg;
    kassert(fetch_arg(arg, 1, &fd_arg));

    // convert argument to proper type
    int fd = (int)fd_arg;

    // make sure that fd refers to an open file
    if (!validate_fd((int)fd)) {
        return ERR_INVAL;
    }
    
    // get the file stored at index fd
    struct proc *p = proc_current();
    kassert(p);
    struct file *file = p->fd_table[fd];

    // close the file and remove it from fd_table
    fs_close_file(file);
    p->fd_table[fd] = NULL;

    return ERR_OK;
}

// int read(int fd, void *buf, size_t count);
static sysret_t
sys_read(void* arg)
{
    // fetch args
    sysarg_t fd_arg, buf_arg, count_arg;
    kassert(fetch_arg(arg, 1, &fd_arg));
    kassert(fetch_arg(arg, 2, &buf_arg));
    kassert(fetch_arg(arg, 3, &count_arg));
    
    // convert arguments to their proper types
    int fd = (int)fd_arg;
    void *buf = (void *)buf_arg;
    size_t count = (size_t)count_arg;

    // validate buffer
    if (!validate_ptr((void*)buf, (size_t)count)) {
        return ERR_FAULT;
    }

    // make sure that fd refers to an open file
    if (!validate_fd((int)fd)) {
        return ERR_INVAL;
    }

    // get the current thread's process
    struct proc *p = proc_current();
    kassert(p);

    // if fd is stdin, read from the console
    if (&stdin == p->fd_table[fd]) {
        return console_read((void*)buf, (size_t)count);
    }

    // run fs_read_file() and return the result
    ssize_t res = fs_read_file(p->fd_table[fd], buf, count, &(p->fd_table[fd]->f_pos));
    return (sysret_t)res;
}

// int write(int fd, const void *buf, size_t count)
static sysret_t
sys_write(void* arg)
{
    // fetch args
    sysarg_t fd_arg, count_arg, buf_arg;
    kassert(fetch_arg(arg, 1, &fd_arg));
    kassert(fetch_arg(arg, 2, &buf_arg));
    kassert(fetch_arg(arg, 3, &count_arg));
    
    // Convert arguments to their proper types
    int fd = (int)fd_arg;
    void *buf = (void *)buf_arg;
    size_t count = (size_t)count_arg;
    
    // validate buffer
    if (!validate_ptr((void*)buf, (size_t)count)) {
        return ERR_FAULT;
    }

    // make sure that fd refers to an open file
    if (!validate_fd((int)fd)) {
        return ERR_INVAL;
    }

    // get the current thread's process
    struct proc *p = proc_current();
    kassert(p);

    // if fd is stdout, write to the console
    if (&stdout == p->fd_table[fd]) {
        return console_write((void*)buf, (size_t)count);
    }

    // run fs_write_file() and return the results
    ssize_t res = fs_write_file(p->fd_table[fd], buf, count, &(p->fd_table[fd]->f_pos));
    return (sysret_t)res;
}

// int link(const char *oldpath, const char *newpath)
static sysret_t
sys_link(void *arg)
{
    sysarg_t oldpath, newpath;

    kassert(fetch_arg(arg, 1, &oldpath));
    kassert(fetch_arg(arg, 2, &newpath));

    if (!validate_str((char*)oldpath) || !validate_str((char*)newpath)) {
        return ERR_FAULT;
    }

    return fs_link((char*)oldpath, (char*)newpath);
}

// int unlink(const char *pathname)
static sysret_t
sys_unlink(void *arg)
{
    sysarg_t pathname;

    kassert(fetch_arg(arg, 1, &pathname));

    if (!validate_str((char*)pathname)) {
        return ERR_FAULT;
    }

    return fs_unlink((char*)pathname);
}

// int mkdir(const char *pathname)
static sysret_t
sys_mkdir(void *arg)
{
    sysarg_t pathname;

    kassert(fetch_arg(arg, 1, &pathname));

    if (!validate_str((char*)pathname)) {
        return ERR_FAULT;
    }

    return fs_mkdir((char*)pathname);
}

// int chdir(const char *path)
static sysret_t
sys_chdir(void *arg)
{
    sysarg_t path;
    struct inode *inode;
    struct proc *p;
    err_t err;

    kassert(fetch_arg(arg, 1, &path));

    if (!validate_str((char*)path)) {
        return ERR_FAULT;
    }

    if ((err = fs_find_inode((char*)path, &inode)) != ERR_OK) {
        return err;
    }

    p = proc_current();
    kassert(p);
    kassert(p->cwd);
    fs_release_inode(p->cwd);
    p->cwd = inode;
    return ERR_OK;
}

// int readdir(int fd, struct dirent *dirent);
static sysret_t
sys_readdir(void *arg)
{
    // fetch args
    sysarg_t fd_arg, dirent_arg;
    kassert(fetch_arg(arg, 1, &fd_arg));
    kassert(fetch_arg(arg, 2, &dirent_arg));
    
    // convert arguments to their proper types
    int fd = (int)fd_arg;
    struct dirent *dirent = (struct dirent*)dirent_arg;
    
    // validate dirent's name
    if (!validate_str((void*)dirent->name)) {
        return ERR_FAULT;
    }

    // make sure that fd refers to an open file
    if (!validate_fd((int)fd)) {
        return ERR_INVAL;
    }

    // get the current thread's process
    struct proc *p = proc_current();
    kassert(p);

    // run fs_readdir() and return the result
    err_t err = fs_readdir(p->fd_table[fd], dirent);
    return (sysret_t)err;
}

// int rmdir(const char *pathname);
static sysret_t
sys_rmdir(void *arg)
{
    sysarg_t pathname;

    kassert(fetch_arg(arg, 1, &pathname));

    if (!validate_str((char*)pathname)) {
        return ERR_FAULT;
    }

    return fs_rmdir((char*)pathname);
}

// int fstat(int fd, struct stat *stat);
static sysret_t
sys_fstat(void *arg)
{
    // fetch args
    sysarg_t fd_arg, stat_arg;
    kassert(fetch_arg(arg, 1, &fd_arg));
    kassert(fetch_arg(arg, 2, &stat_arg));
    
    // convert arguments to their proper types
    int fd = (int)fd_arg;
    struct stat *stat = (struct stat*)stat_arg;

    // make sure that fd refers to an open file
    if (!validate_fd((int)fd)) {
        return ERR_INVAL;
    }

    // get the file stored at index fd
    struct proc *p = proc_current();
    kassert(p);
    struct file *file = p->fd_table[fd];

    // throw an error if it is stdin or stdout
    if (file == &stdin || file == &stdout) {
        return ERR_INVAL;
    }

    // validate stat's address
    if (!validate_ptr((void*)stat, sizeof(struct stat))) {
        return ERR_FAULT;
    }

    // copy file's ftype to stat's ftype
    stat->ftype = (int)file->f_inode->i_ftype;
    stat->inode_num = (int)file->f_inode->i_inum;
    stat->size = (size_t)file->f_inode->i_size;

    return ERR_OK;
}

// void *sbrk(size_t increment);
static sysret_t
sys_sbrk(void *arg)
{    
    // Retrieve the increment argument
    sysarg_t increment_arg;
    kassert(fetch_arg(arg, 1, &increment_arg));
    size_t increment = (size_t)increment_arg;

    // Get the current process
    struct proc *p = proc_current();
    kassert(p);

    vaddr_t old_bound = NULL;
    // call memregion_extend to extend the heap by increment
    if (memregion_extend(p->as.heap, increment, &old_bound) != ERR_OK) {
        // Error if memregion_extend fails
        return ERR_NOMEM;
    }

    return old_bound;
}

// void memifo();
static sysret_t
sys_meminfo(void *arg)
{
    as_meminfo(&proc_current()->as);
    return ERR_OK;
}

// int dup(int fd);
static sysret_t
sys_dup(void *arg)
{
    sysarg_t fd_arg;

    kassert(fetch_arg(arg, 1, &fd_arg));
    
    // Convert argument to its proper type
    int fd = (int)fd_arg;

    // make sure that fd refers to an open file
    if (!validate_fd((int)fd)) {
        return ERR_INVAL;
    }

    // get the current thread's process
    struct proc *p = proc_current();
    kassert(p);

    struct file *file = p->fd_table[fd];

    // reopen the file
    fs_reopen_file(file);
    
    // allocate a spot on the fd table for file
    int new_fd = alloc_fd(file);

    // return the fd number
    return (sysret_t) new_fd;
}

// int pipe(int* fds);
static sysret_t
sys_pipe(void* arg)
{
    // fetch arg
    sysarg_t fds_arg;
    kassert(fetch_arg(arg, 1, &fds_arg));
    
    // Convert argument to its proper type
    int *fds = (int *)fds_arg;
    
    // validate fds' address
    if (!validate_ptr((void*)fds, sizeof(int) * 2)) {
        return ERR_FAULT;
    }

    // allocate the pipe, making sure it worked
    pipe *pipe = pipe_alloc();
    if (pipe == NULL) {
        return ERR_NOMEM;
    }

    // store the two file-descriptor-table indices associated with the struct pipe object
    // returned from pipe_alloc in the provided fds array, and return ERR_OK.

    // get an fd for the read end, making sure it worked
    fds[0] = alloc_fd(pipe->read);
    if (fds[0] == ERR_NOMEM) {
        return ERR_NOMEM;
    }
    
    // get an fd for the write end
    fds[1] = alloc_fd(pipe->write);

    // if the second fd has an error, close the first one
    if (fds[1] == ERR_NOMEM) {

        // get the file stored at index fd
        struct proc *p = proc_current();
        kassert(p);
        struct file *file = p->fd_table[fds[0]];

        // close the file and remove it from fd_table
        fs_close_file(file);
        p->fd_table[fds[0]] = NULL;

        return ERR_NOMEM;
    }

    return ERR_OK;
}

// void sys_info(struct sys_info *info);
static sysret_t
sys_info(void* arg)
{
    sysarg_t info;

    kassert(fetch_arg(arg, 1, &info));

    if (!validate_ptr((void*)info, sizeof(struct sys_info))) {
        return ERR_FAULT;
    }
    // fill in using user_pgfault 
    ((struct sys_info*)info)->num_pgfault = user_pgfault;
    return ERR_OK;
}

// void halt();
static sysret_t 
sys_halt(void* arg)
{
    shutdown();
    panic("shutdown failed");
}


sysret_t
syscall(int num, void *arg)
{
    kassert(proc_current());
    if(num > 0 && num < NELEM(syscalls) && syscalls[num]) {
        return syscalls[num](arg);
    } else {
        panic("Unknown system call");
    }
}

