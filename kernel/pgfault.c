#include <kernel/proc.h>
#include <kernel/console.h>
#include <kernel/trap.h>
#include <lib/errcode.h>
#include <kernel/vpmap.h>
#include <lib/string.h>
#include <arch/mmu.h>
#include <kernel/vm.h>


size_t user_pgfault = 0;


void
handle_page_fault(vaddr_t fault_addr, int present, int write, int user) {
    if (user) {
        __sync_add_and_fetch(&user_pgfault, 1);
    }
    // turn on interrupt now that we have the fault address 
    intr_set_level(INTR_ON);

    // get parent process
    struct proc *p = proc_current();
    kassert(p);
    
    if (fault_addr <= p->as.heap->end && fault_addr >= p->as.heap->start){
        // heap stuff
        paddr_t paddr;
        // allocate a physical page
        if (pmem_alloc(&paddr) != ERR_OK) {
            return;
        }
        // map the p-page
        vpmap_map(p->as.vpmap, fault_addr, paddr, 1, MEMPERM_URW);
        // set it to 0 with memset
        memset((void*) fault_addr, 0, pg_size);
    }
    else if (fault_addr < USTACK_UPPERBOUND - pg_size && fault_addr > USTACK_LOWERBOUND){
        // stack stuff
        paddr_t paddr;
        // allocate a physical page
        if (pmem_alloc(&paddr) != ERR_OK) {
            return;
        }
        // map the p-page
        vpmap_map(p->as.vpmap, fault_addr, paddr, 1, MEMPERM_URW);
        // set it to 0 with memset
        memset((void*) fault_addr, 0, pg_size);
    }
    else{
        proc_exit(-1);
    }

}
