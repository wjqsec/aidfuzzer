#ifndef XX_IRQ_INCLUDED
#define XX_IRQ_INCLUDED

#include "xx.h"


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

void add_memory_access_watchpoint(int irq, uint32_t addr, hw_addr isr);
void add_unsolved_func_ptr(int irq, uint32_t addr, hw_addr isr);
void add_dependency_func_ptr(int irq,uint32_t addr, hw_addr isr);
#endif