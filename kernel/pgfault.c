#include <kernel/proc.h>
#include <kernel/console.h>
#include <kernel/trap.h>
#include <lib/errcode.h>
#include <kernel/vpmap.h>
#include <lib/string.h>


size_t user_pgfault = 0;


void
handle_page_fault(vaddr_t fault_addr, int present, int write, int user) {
    if (user) {
        __sync_add_and_fetch(&user_pgfault, 1);
    }
    // turn on interrupt now that we have the fault address 
    intr_set_level(INTR_ON);


    paddr_t paddr;

    if (pmem_alloc(&paddr) != ERR_OK) {
        return;
    }

    // fault_addr = kmap_p2v(paddr);
    
    // get parent process
    struct proc *p = proc_current();
    kassert(p);

    vpmap_map(p->as.vpmap, fault_addr, paddr, 1, MEMPERM_URW);

    memset((void*) fault_addr, 0, pg_size);


    if (user) {
        // kprintf("fault address %p, present %d, write %d, user %d\n", fault_addr, present, write, user);
        return;
        // proc_exit(0);
        // panic("unreachable");
    } else {
        // kprintf("fault addr %p\n", fault_addr);
        panic("Kernel error in page fault handler\n");
    }
}
