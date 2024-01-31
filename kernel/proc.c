#include <kernel/console.h>
#include <kernel/proc.h>
#include <kernel/kmalloc.h>
#include <kernel/thread.h>
#include <kernel/list.h>
#include <kernel/fs.h>
#include <kernel/vpmap.h>
#include <arch/elf.h>
#include <arch/trap.h>
#include <arch/mmu.h>
#include <lib/errcode.h>
#include <lib/stddef.h>
#include <lib/string.h>

List ptable; // process table
struct spinlock ptable_lock;
struct spinlock pid_lock;
static int pid_allocator;
struct kmem_cache *proc_allocator;

/* go through process table */
static void ptable_dump(void);
/* helper function for loading process's binary into its address space */ 
static err_t proc_load(struct proc *p, char *path, vaddr_t *entry_point);
/* helper function to set up the stack */
static err_t stack_setup(struct proc *p, char **argv, vaddr_t* ret_stackptr);
/* tranlsates a kernel vaddr to a user stack address, assumes stack is a single page */
#define USTACK_ADDR(addr) (pg_ofs(addr) + USTACK_UPPERBOUND - pg_size);

static struct proc*
proc_alloc()
{
    struct proc* p = (struct proc*) kmem_cache_alloc(proc_allocator);
    if (p != NULL) {
        spinlock_acquire(&pid_lock);
        p->pid = pid_allocator++;
        spinlock_release(&pid_lock);
    }
    return p;
}

#pragma GCC diagnostic ignored "-Wunused-function"
static void
ptable_dump(void)
{
    kprintf("ptable dump:\n");
    spinlock_acquire(&ptable_lock);
    for (Node *n = list_begin(&ptable); n != list_end(&ptable); n = list_next(n)) {
        struct proc *p = list_entry(n, struct proc, proc_node);
        kprintf("Process %s: pid %d\n", p->name, p->pid);
    }
    spinlock_release(&ptable_lock);
    kprintf("\n");
}

void
proc_free(struct proc* p)
{
    kmem_cache_free(proc_allocator, p);
}

void
proc_sys_init(void)
{
    list_init(&ptable);
    spinlock_init(&ptable_lock);
    spinlock_init(&pid_lock);
    proc_allocator = kmem_cache_create(sizeof(struct proc));
    kassert(proc_allocator);
}

/*
 * Allocate and initialize basic proc structure
*/
static struct proc*
proc_init(char* name)
{
    struct super_block *sb;
    inum_t inum;
    err_t err;

    struct proc *p = proc_alloc();
    if (p == NULL) {
        return NULL;
    }

    // initialize the child_pids table to be NULL
    for (size_t i = 0; i < PROC_MAX_CHILDREN; i++) {
        p->exited_children[i].pid = NULL;
        p->exited_children[i].status = NULL;
        p->exited_children[i].waited_on = False;
    }

    if (as_init(&p->as) != ERR_OK) {
        proc_free(p);
        return NULL;
    }

    size_t slen = strlen(name);
    slen = slen < PROC_NAME_LEN-1 ? slen : PROC_NAME_LEN-1;
    memcpy(p->name, name, slen);
    p->name[slen] = 0;

    list_init(&p->threads);

    // initialize stdin and stdout to be file descriptor 0 and 1 respectively
    p->fd_table[0] = &stdin;
    p->fd_table[1] = &stdout;

    // initialize the fd table to be NULL
    for (size_t i = 2; i < PROC_MAX_FILE; i++) {
        p->fd_table[i] = NULL;
    }

	// cwd for all processes are root for now
    sb = root_sb;
	inum = root_sb->s_root_inum;
    if ((err = fs_get_inode(sb, inum, &p->cwd)) != ERR_OK) {
        as_destroy(&p->as);
        proc_free(p);
        return NULL;
    }

    // initialize the parent pointer to NULL
    p->parent = NULL;

    spinlock_init(&p->cv_lock);
    condvar_init(&p->cv);

    return p;
}

err_t
proc_spawn(char* name, char** argv, struct proc **p)
{
    err_t err;
    struct proc *proc;
    struct thread *t;
    vaddr_t entry_point;
    vaddr_t stackptr;

    if ((proc = proc_init(name)) == NULL) {
        return ERR_NOMEM;
    }

    // save a pointer to the parent process in the child
    if (p != &init_proc) {
        proc->parent = proc_current();
    }
    

    // load binary of the process
    if ((err = proc_load(proc, name, &entry_point)) != ERR_OK) {
        goto error;
    }


    // set up stack and allocate its memregion 
    if ((err = stack_setup(proc, argv, &stackptr)) != ERR_OK) {
        goto error;
    }

    if ((t = thread_create(proc->name, proc, DEFAULT_PRI)) == NULL) {
        err = ERR_NOMEM;
        goto error;
    }

    // add to ptable
    spinlock_acquire(&ptable_lock);
    list_append(&ptable, &proc->proc_node);
    spinlock_release(&ptable_lock);

    // set up trapframe for a new process
    tf_proc(t->tf, t->proc, entry_point, stackptr);
    thread_start_context(t, NULL, NULL);

    // fill in allocated proc
    if (p) {
        *p = proc;
    }
    return ERR_OK;
error:
    as_destroy(&proc->as);
    proc_free(proc);
    return err;
}

struct proc*
proc_fork()
{
    // get parent process
    struct proc *p = proc_current();
    kassert(p);  // caller of fork must be a process

    // init child process
    // kprintf("hello\n");
    struct proc *p_fork;
    p_fork = proc_init("test");

    // kprintf("hello\n");


    // save a pointer to the parent process in the child 
    p_fork->parent = p;

    // copy address space and fd table from parent to child
    as_copy_as(&(p->as), &(p_fork->as));
    for (int i = 0; i < PROC_MAX_FILE; i++) {
        p_fork->fd_table[i] = p->fd_table[i];
        
        // reopen all files
        if (p_fork->fd_table[i] != NULL) {
            fs_reopen_file(p_fork->fd_table[i]);
        }
    }

    // add child process to ptable
    spinlock_acquire(&ptable_lock);
    list_append(&ptable, &p_fork->proc_node);
    spinlock_release(&ptable_lock);
    
    // create child's thread
    struct thread *t_fork;
    if ((t_fork = thread_create(p_fork->name, p_fork, DEFAULT_PRI)) == NULL) {
        return NULL;
    }

    // set up trapframe for a new process
    *t_fork->tf = *thread_current()->tf;
    // set return value of the trapframe
    tf_set_return(t_fork->tf, 0);
    // start the thread
    thread_start_context(t_fork, NULL, NULL);

    

    return p_fork;
}

struct proc*
proc_current()
{
    return thread_current()->proc;
}

void
proc_attach_thread(struct proc *p, struct thread *t)
{
    kassert(t);
    if (p) {
        list_append(&p->threads, &t->thread_node);
    }
}

bool
proc_detach_thread(struct thread *t)
{
    bool last_thread = False;
    struct proc *p = t->proc;
    if (p) {
        list_remove(&t->thread_node);
        last_thread = list_empty(&p->threads);
    }
    return last_thread;
}

int
proc_wait(pid_t pid, int* status)
{
    // kprintf("wait\n");
    struct proc *p = proc_current();
    kassert(p);
    pid_t ret_pid = NULL;

    // kprintf("wait2\n");

    bool child_exists = False;
    spinlock_acquire(&ptable_lock);

    // make sure that the child with the desired pid exists, or any child if pid == ANY_CHILD
    for (Node *n = list_begin(&ptable); n != list_end(&ptable); n = list_next(n)) {
        struct proc *ptable_p = list_entry(n, struct proc, proc_node);
        if (ptable_p->parent == p) {
            if (pid == ANY_CHILD) {
                child_exists = True;
                break;
            } else {
                if (ptable_p->pid == pid) {
                    child_exists = True;
                    break;
                }
            }
        }
    }

    // if we did not find a child, ____________
    if (!child_exists) {
        for (int i = 0; i < PROC_MAX_CHILDREN; i++) {
            if ((pid == p->exited_children[i].pid || (pid == ANY_CHILD && p->exited_children[i].pid != NULL)) && !(p->exited_children[i].waited_on)) {
                p->exited_children[i].waited_on = True;
                if (status != NULL) {
                    *status = p->exited_children[i].status;
                }
                spinlock_release(&ptable_lock);
                return p->exited_children[i].pid;
            }
        }
        spinlock_release(&ptable_lock);
        return ERR_CHILD;
    }
    spinlock_release(&ptable_lock);



    spinlock_acquire(&p->cv_lock);
    bool child_found = False;

    if (pid == ANY_CHILD) {
        while (!child_found) {
            // while (p->child_pids[next_empty] == NULL) {
                // kprintf("wait3.5\n");
                condvar_wait(&p->cv, &p->cv_lock);
            // }
            // kprintf("wait3.6\n");

            for (int i = 0; i < PROC_MAX_CHILDREN; i++) {
                if (p->exited_children[i].pid != NULL && !(p->exited_children[i].waited_on)) {
                    ret_pid = p->exited_children[i].pid;
                    p->exited_children[i].waited_on = True;
                    if (status != NULL) {
                        *status = p->exited_children[i].status;
                    }
                    child_found = True;
                    break;
                }
            }
        }
    } else {
        // check for the desired pid in the list of child pids
        while (!child_found) {
            // kprintf("wait4\n");

            condvar_wait(&p->cv, &p->cv_lock);
            
            for (int i = 0; i < PROC_MAX_CHILDREN; i++) {
                // for (int j = 0; j < 10; j++) {
                //     kprintf("%d ", p->exited_children[j].pid);
                // }
                // kprintf("\n");
                if (p->exited_children[i].pid == pid) {
                    // if the child we are trying to wait on has already exited, return ERR_CHILD 
                    if (p->exited_children[i].waited_on == True) {
                        return ERR_CHILD;
                    }
                    // kprintf("wait4.5\n");
                    ret_pid = p->exited_children[i].pid;
                    child_found = True;
                    p->exited_children[i].waited_on = True;
                    if (status != NULL) {
                        *status = p->exited_children[i].status;
                    }
                    break;
                }
            }
        }
    }
    // kprintf("wait6\n");

    spinlock_release(&p->cv_lock);
    // kprintf("wait7\n");

    
    // kprintf("wait8\n");

    // *status = 0;
    return ret_pid;
}

void
proc_exit(int status)
{
    struct thread *t = thread_current();
    struct proc *p = proc_current();

    // detach current thread, switch to kernel page table
    // free current address space if proc has no more threads
    // order matters here
    proc_detach_thread(t);
    t->proc = NULL;
    vpmap_load(kas->vpmap);
    as_destroy(&p->as);

    // release process's cwd
    fs_release_inode(p->cwd);
 
    list_remove(&p->proc_node);
    // close all files in fd table that arent null
    for (int i = 0; i < PROC_MAX_FILE; i++) {
        if (p->fd_table[i] != NULL) {
            fs_close_file(p->fd_table[i]);
        }
    }

    if (p->parent != NULL) {
        spinlock_acquire(&p->parent->cv_lock);
        // update exited_children array of parent
        for (int i = 0; i < PROC_MAX_CHILDREN; i++) {
            if (p->parent->exited_children[i].pid == p->pid) {
                p->parent->exited_children[i].status = status;
                break;
            } else {
                if (p->parent->exited_children[i].pid == NULL) {
                    p->parent->exited_children[i].pid = p->pid;
                    p->parent->exited_children[i].status = status;
                    // kprintf("cpid=%d\n", p->pid);
                    // kprintf("cstatus=%d\n", status);
                    break;
                }  
            }
        }
        condvar_signal(&p->parent->cv);
        spinlock_release(&p->parent->cv_lock);
    }

    for (Node *n = list_begin(&ptable); n != list_end(&ptable); n = list_next(n)) {
        struct proc *ptable_p = list_entry(n, struct proc, proc_node);
        if (ptable_p->parent == p) {
            ptable_p->parent = NULL;
        }
    }

    proc_free(p);

    thread_exit(status);
}

/* helper function for loading process's binary into its address space */ 
static err_t
proc_load(struct proc *p, char *path, vaddr_t *entry_point)
{
    int i;
    err_t err;
    offset_t ofs = 0;
    struct elfhdr elf;
    struct proghdr ph;
    struct file *f;
    paddr_t paddr;
    vaddr_t vaddr;
    vaddr_t end = 0;

    if ((err = fs_open_file(path, FS_RDONLY, 0, &f)) != ERR_OK) {
        return err;
    }

    // check if the file is actually an executable file
    if (fs_read_file(f, (void*) &elf, sizeof(elf), &ofs) != sizeof(elf) || elf.magic != ELF_MAGIC) {
        return ERR_INVAL;
    }

    // read elf and load binary
    for (i = 0, ofs = elf.phoff; i < elf.phnum; i++) {
        if (fs_read_file(f, (void*) &ph, sizeof(ph), &ofs) != sizeof(ph)) {
            return ERR_INVAL;
        }
        if(ph.type != PT_LOAD)
            continue;

        if(ph.memsz < ph.filesz || ph.vaddr + ph.memsz < ph.vaddr) {
            return ERR_INVAL;
        }

        memperm_t perm = MEMPERM_UR;
        if (ph.flags & PF_W) {
            perm = MEMPERM_URW;
        }

        // found loadable section, add as a memregion
        struct memregion *r = as_map_memregion(&p->as, pg_round_down(ph.vaddr), 
            pg_round_up(ph.memsz + pg_ofs(ph.vaddr)), perm, NULL, ph.off, False);
        if (r == NULL) {
            return ERR_NOMEM;
        }
        end = r->end;

        // pre-page in code and data, may span over multiple pages
        int count = 0;
        size_t avail_bytes;
        size_t read_bytes = ph.filesz;
        size_t pages = pg_round_up(ph.memsz + pg_ofs(ph.vaddr)) / pg_size;
        // vaddr may start at a nonaligned address
        vaddr = pg_ofs(ph.vaddr);
        while (count < pages) {
            // allocate a physical page and zero it first
            if ((err = pmem_alloc(&paddr)) != ERR_OK) {
                return err;
            }
            vaddr += kmap_p2v(paddr);
            memset((void*)pg_round_down(vaddr), 0, pg_size);
            // calculate how many bytes to read from file
            avail_bytes = read_bytes < (pg_size - pg_ofs(vaddr)) ? read_bytes : (pg_size - pg_ofs(vaddr));
            if (avail_bytes && fs_read_file(f, (void*)vaddr, avail_bytes, &ph.off) != avail_bytes) {
                return ERR_INVAL;
            }
            // map physical page with code/data content to expected virtual address in the page table
            if ((err = vpmap_map(p->as.vpmap, ph.vaddr+count*pg_size, paddr, 1, perm)) != ERR_OK) {
                return err;
            }
            read_bytes -= avail_bytes;
            count++;
            vaddr = 0;
        }
    }
    *entry_point = elf.entry;

    // create memregion for heap after data segment
    if ((p->as.heap = as_map_memregion(&p->as, end, 0, MEMPERM_URW, NULL, 0, 0)) == NULL) {
        return ERR_NOMEM;
    }

    return ERR_OK;
}

err_t
stack_setup(struct proc *p, char **argv, vaddr_t* ret_stackptr)
{
    err_t err;
    paddr_t paddr;
    vaddr_t stackptr;
    vaddr_t stacktop = USTACK_UPPERBOUND-pg_size;

    // allocate a page of physical memory for stack
    if ((err = pmem_alloc(&paddr)) != ERR_OK) {
        return err;
    }
    memset((void*) kmap_p2v(paddr), 0, pg_size);
    // create memregion for stack
    if (as_map_memregion(&p->as, stacktop, pg_size, MEMPERM_URW, NULL, 0, False) == NULL) {
        err = ERR_NOMEM;
        goto error;
    }
    // map in first stack page
    if ((err = vpmap_map(p->as.vpmap, stacktop, paddr, 1, MEMPERM_URW)) != ERR_OK) {
        goto error;
    }
    // kernel virtual address of the user stack, points to top of the stack
    // as you allocate things on stack, move stackptr downward.
    stackptr = kmap_p2v(paddr) + pg_size;

    /* Your Code Here.  */
    // allocate space for fake return address, argc, argv
    // remove following line when you actually set up the stack
    stackptr -= 3 * sizeof(void*);

    // translates stackptr from kernel virtual address to user stack address
    *ret_stackptr = USTACK_ADDR(stackptr); 
    return err;
error:
    pmem_free(paddr);
    return err;
}
