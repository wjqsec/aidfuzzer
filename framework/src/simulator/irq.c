#include "irq.h"

#include "utl.h"
#include "model.h"
#include "simulator.h"
#include <stdio.h>


#define MAX_IRQ_MODEL_MEMORY_NUM 0x100


typedef struct _UNSOLVED_FUNC_PTR
{
  hw_addr addr;
  int num_vals;
  hw_addr vals[MAX_IRQ_MODEL_MEMORY_NUM];
}UNSOLVED_FUNC_PTR;

typedef struct _IRQ_GLOBAL_STATE
{
    uint8_t mem_access_trigger_irq_times;
    hw_addr mem[MAX_IRQ_MODEL_MEMORY_NUM];

    hw_addr mmio[MAX_IRQ_MODEL_MEMORY_NUM];

    int num_unsolved_func_ptrs;
    UNSOLVED_FUNC_PTR unsolved_func_ptrs[MAX_IRQ_MODEL_MEMORY_NUM]; 

    int num_dependency_ptrs;
    hw_addr dependency_ptrs[MAX_IRQ_MODEL_MEMORY_NUM];

}IRQ_GLOBAL_STATE;


typedef struct _IRQ_RUNTIME_STATE
{

    int num_solved_dependency_ptrs;
    hw_addr solved_dependency_ptrs[MAX_IRQ_MODEL_MEMORY_NUM];
    uint8_t mem_access_trigger_irq_times_count;
}IRQ_RUNTIME_STATE;



typedef struct _IRQ_VALUES
{
    int num_addrs;
    hw_addr addrs[MAX_IRQ_MODEL_MEMORY_NUM];
}IRQ_VALUES;

typedef struct _IRQ_ADDRS
{
    int num_addrs;
    hw_addr addrs[MAX_IRQ_MODEL_MEMORY_NUM];
}IRQ_ADDRS;

#define MAX_NUM_IRQ_VECBASES 5
struct IRQ_MODEL
{
    int num_irq_vecbases;
    hw_addr irq_vecbases[MAX_NUM_IRQ_VECBASES];

    int num_enabled_irqs;
    irq_val enabled_irqs[NVIC_MAX_VECTORS];

    IRQ_ADDRS irq_addrs[NVIC_MAX_VECTORS];
    IRQ_VALUES irq_values[NVIC_MAX_VECTORS];

    IRQ_GLOBAL_STATE global_state[NVIC_MAX_VECTORS];
    IRQ_RUNTIME_STATE runtime_state[NVIC_MAX_VECTORS];

    int idel_times;


}irq_model;


bool is_irq_ready(irq_val irq)
{
    uint32_t val;
    for (int i = 0; i < irq_model.global_state[irq].num_dependency_ptrs; i ++)
    {
        read_ram(irq_model.global_state[irq].dependency_ptrs[i],4,&val);
        if(val == 0)
            return  false;
    }
    return true;
    // return irq_model.global_state[irq].num_dependency_ptrs == irq_model.runtime_state[irq].num_solved_dependency_ptrs;
}
bool is_irq_access_memory(irq_val irq)
{
    return irq_model.global_state[irq].mem_access_trigger_irq_times;
}
void clear_irq_runtime_state(irq_val irq)
{
    irq_model.runtime_state[irq].num_solved_dependency_ptrs = 0;
    irq_model.runtime_state[irq].mem_access_trigger_irq_times_count = 0;
}
void clear_enabled_irq_runtime_state()
{
    for(int i = 0; i < irq_model.num_enabled_irqs ; i++)
    {
        clear_irq_runtime_state(irq_model.enabled_irqs[i]);
    }
}
void clear_global_state(irq_val irq)
{
    memset(&irq_model.global_state[irq], 0, sizeof(IRQ_GLOBAL_STATE));
}

void irq_on_set_nvic_vec_entry(irq_val irq)
{
    hw_addr addr;
    hw_addr value;


    addr = get_nvic_vecbase() + 4 * irq;
    read_ram(addr,sizeof(value),&value);


    if(value == 0)
        return;
    if(!find_value_32(irq_model.irq_values[irq].addrs,  irq_model.irq_values[irq].num_addrs, value))
    {
        irq_model.irq_values[irq].addrs[irq_model.irq_values[irq].num_addrs++] = value;
        clear_global_state(irq);
        clear_irq_runtime_state(irq);
        model_irq(irq);
        
    }
    if(!find_value_32(irq_model.irq_addrs[irq].addrs,  irq_model.irq_addrs[irq].num_addrs, addr))
    {
        irq_model.irq_addrs[irq].addrs[irq_model.irq_addrs[irq].num_addrs++] = addr;
        insert_nostop_watchpoint(addr,4,QEMU_PLUGIN_MEM_W_ ,nostop_watchpoint_exec_overwrite_vec,(void*)(uint64_t)irq);
    }
}

void irq_on_set_new_vecbase(hw_addr addr)
{

    if(find_value_32(irq_model.irq_vecbases,irq_model.num_irq_vecbases,addr))
        return;
    irq_model.irq_vecbases[irq_model.num_irq_vecbases++] = addr;
    for(int i = 0 ; i < irq_model.num_enabled_irqs ; i++)
    {
        irq_on_set_nvic_vec_entry(irq_model.enabled_irqs[i]);
    }
}

void irq_on_mem_access(int irq,hw_addr addr)
{
    bool insert_irq;
    if(!is_irq_ready(irq))
        return;

    if(get_arm_v7m_is_handler_mode() != ARMV7M_EXCP_PENDSV && get_arm_v7m_is_handler_mode() != 0)
        return;
    
    
    if(find_value_32(irq_model.global_state[irq].mem,irq_model.global_state[irq].mem_access_trigger_irq_times,addr))
    {
        irq_model.runtime_state[irq].mem_access_trigger_irq_times_count++;
        if(irq_model.runtime_state[irq].mem_access_trigger_irq_times_count > irq_model.global_state[irq].mem_access_trigger_irq_times)
        {
            insert_irq = insert_nvic_intc(irq);
            irq_model.runtime_state[irq].mem_access_trigger_irq_times_count = 0;
            if(insert_irq) 
            {
                #ifdef DBG
                fprintf(flog,"%d->insert mem access irq %d\n",run_index,irq);
                #endif
            }
        }
        
    }

}
void irq_on_mmio_access(int irq,hw_addr addr)
{

}
void irq_on_unsolved_func_ptr_write(int irq, uint32_t addr, uint32_t val)
{
    if(val == 0)
        return;
    for(int i = 0; i < irq_model.global_state[irq].num_unsolved_func_ptrs; i ++)
    {
        if(irq_model.global_state[irq].unsolved_func_ptrs[i].addr == addr)
        {
            if(!find_value_32(irq_model.global_state[irq].unsolved_func_ptrs[i].vals,irq_model.global_state[irq].unsolved_func_ptrs[i].num_vals,addr))
            {
                irq_model.global_state[irq].unsolved_func_ptrs[i].vals[irq_model.global_state[irq].unsolved_func_ptrs[i].num_vals++] = addr;
                model_irq(irq);
            }
        }

    }
}
void irq_on_dependency_ptr_write(int irq, uint32_t addr, uint32_t val)
{
    if(val == 0)
        return;
    if(!find_value_32(irq_model.runtime_state[irq].solved_dependency_ptrs, irq_model.runtime_state[irq].num_solved_dependency_ptrs,addr))
    {
        irq_model.runtime_state[irq].solved_dependency_ptrs[irq_model.runtime_state[irq].num_solved_dependency_ptrs++] = addr;
    }
}
void irq_on_enable_nvic_irq(int irq)
{
    if(!find_value_16(irq_model.enabled_irqs,irq_model.num_enabled_irqs,irq))
    {
        irq_model.enabled_irqs[irq_model.num_enabled_irqs++] = irq;
        irq_on_set_nvic_vec_entry(irq);
    }
        
}
void irq_on_idel()
{
    #ifdef DBG
        fprintf(flog,"%d->try insert idel is_handler_mode:%d num_enabled_irqs:%d ready:",run_index,get_arm_v7m_is_handler_mode(),irq_model.num_enabled_irqs);
        for(int i = 0; i < irq_model.num_enabled_irqs; i++)
        {
            if( is_irq_access_memory(irq_model.enabled_irqs[i]))
            {
                fprintf(flog,"%d  ",irq_model.enabled_irqs[i]);
            }
        }
        fprintf(flog,"\n");
    #endif
    if(get_arm_v7m_is_handler_mode() != ARMV7M_EXCP_PENDSV && get_arm_v7m_is_handler_mode() != 0)
        return;
    
    if(irq_model.num_enabled_irqs == 0)
        return;
    int try_irq;
    bool found_valid_irq = false;
    for(int i = 0; i < irq_model.num_enabled_irqs; i++)
    {
        try_irq = irq_model.enabled_irqs[irq_model.idel_times % irq_model.num_enabled_irqs];
        irq_model.idel_times++;
        if(is_irq_ready(try_irq) && is_irq_access_memory(try_irq))
        // if(is_irq_access_memory(try_irq))
        {
            found_valid_irq = true;
            break;
        }
    }
    if(!found_valid_irq)
        return;
    bool insert_irq = insert_nvic_intc(try_irq);
    if(insert_irq)
    {
        #ifdef DBG
        fprintf(flog,"%d->insert idel irq %d\n",run_index,try_irq);
        #endif
    }
    
}
void irq_on_new_run()
{
    irq_on_set_new_vecbase(get_nvic_vecbase());
    clear_enabled_irq_runtime_state();
    irq_model.idel_times = 0;
}
void irq_on_init()
{
    char cmd[PATH_MAX];
    sprintf(cmd,"rm %s/%s",model_dir,IRQ_MODEL_FILENAME);
    system(cmd);
    memset(&irq_model, 0, sizeof(irq_model));
}
void add_memory_access_watchpoint(int irq, uint32_t addr)
{
    if(find_value_32(irq_model.global_state[irq].mem,irq_model.global_state[irq].mem_access_trigger_irq_times,addr))
        return;
    insert_nostop_watchpoint(addr,4,QEMU_PLUGIN_MEM_R_ ,nostop_watchpoint_exec_mem,(void*)(uint64_t)irq);
    irq_model.global_state[irq].mem[irq_model.global_state[irq].mem_access_trigger_irq_times++] = addr;
    printf("insert_nostop_watchpoint mem irq:%d addr:%x\n",irq,addr);
}
void add_unsolved_func_ptr(int irq, uint32_t addr)
{
    for(int i = 0 ; i < irq_model.global_state[irq].num_unsolved_func_ptrs ; i++)
    {
        if(irq_model.global_state[irq].unsolved_func_ptrs[i].addr == addr)
            return;
    }

    insert_nostop_watchpoint(addr,4,QEMU_PLUGIN_MEM_W_ ,nostop_watchpoint_exec_unresolved_func_ptr,(void*)(uint64_t)irq);
    irq_model.global_state[irq].unsolved_func_ptrs[irq_model.global_state[irq].num_unsolved_func_ptrs++].addr = addr;
    printf("insert_nostop_watchpoint func irq:%d addr:%x\n",irq,addr);
}
void add_dependency_func_ptr(int irq,uint32_t addr)
{
    if(find_value_32(irq_model.global_state[irq].dependency_ptrs,irq_model.global_state[irq].num_dependency_ptrs,addr))
        return;
    // insert_nostop_watchpoint(addr,4,QEMU_PLUGIN_MEM_W_ ,nostop_watchpoint_exec_denpendency,(void*)(uint64_t)irq);
    irq_model.global_state[irq].dependency_ptrs[irq_model.global_state[irq].num_dependency_ptrs++] = addr;
    printf("insert dependency irq:%d addr:%x\n",irq,addr);
}