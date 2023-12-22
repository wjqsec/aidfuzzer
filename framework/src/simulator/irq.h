#ifndef XX_IRQ_INCLUDED
#define XX_IRQ_INCLUDED

#include "xx.h"
#include <set>
#include <map>
#include <vector>


using namespace std;
struct WATCHPOINT
{
    NOSTOP_WATCHPOINT *point;
    hw_addr addr;
};


struct IRQ_N_STATE
{
    bool toend;
    hw_addr isr;
    int mem_access_trigger_irq_times_count;

    map<hw_addr,WATCHPOINT*> *mem_addr;
    set<void*> *dependency_nullptr;
    map<hw_addr,WATCHPOINT*> *func_nullptr;
    map<hw_addr,hw_addr> *func_resolved_ptrs;
};


struct IRQ_N_MODEL
{
    bool enabled;
    hw_addr current_id;
    set<hw_addr> *vec_watchpoints;
    map<hw_addr,IRQ_N_STATE*> *state;
};

void irq_on_set_new_vecbase(hw_addr addr);
void irq_on_mem_access(int irq,hw_addr addr);
void irq_on_overwrite_vec_entry(irq_val irq,hw_addr vaddr);
void irq_on_mmio_access(int irq,uint32_t addr);
void irq_on_unsolved_func_ptr_write(int irq, uint32_t addr, uint32_t val);
void irq_on_enable_nvic_irq(int irq);
void irq_on_disable_nvic_irq(int irq);
void irq_on_idel();
void irq_on_new_run();
void irq_on_init();
void irq_on_snapshot();
IRQ_N_STATE *get_void_state();
void add_memory_access_watchpoint(int irq, uint32_t addr, hw_addr isr);
void add_unsolved_func_ptr(int irq, uint32_t addr, hw_addr isr);
void add_dependency_func_ptr(int irq,uint32_t addr, hw_addr isr);
#endif