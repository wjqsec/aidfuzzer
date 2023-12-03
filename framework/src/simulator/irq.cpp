#include <map>
#include <vector>
#include <set>
#include <unistd.h>
#include "irq.h"

#include "utl.h"
#include "model.h"
#include "simulator.h"
#include "config.h"
#include <stdio.h>

using namespace std;
#define INVALID_VECADDR 0
#define MAX_NVIC_IRQ 250






map<irq_val,IRQ_N_MODEL*> models;
set<irq_val> enabled_irqs;
uint64_t idle_count = 0;

IRQ_N_STATE *get_void_state()
{
    IRQ_N_STATE* state = new IRQ_N_STATE();
    state->mem_addr = new map<hw_addr,WATCHPOINT*>();
    state->dependency_nullptr = new set<void*>();
    state->func_nullptr = new map<hw_addr,WATCHPOINT*>();
    state->func_resolved_ptrs = new set<hw_addr>();
    state->mem_access_trigger_irq_times_count = 0;
    return state;
}
__attribute__((always_inline)) hw_addr get_current_isr(irq_val irq)
{
    return models[irq]->current_isr;
}
__attribute__((always_inline)) hw_addr get_current_id(irq_val irq)
{
    return models[irq]->current_id;
}

__attribute__((always_inline)) bool is_isr_modeled(irq_val irq,hw_addr id)
{
    return models[irq]->state->find(id) != models[irq]->state->end();
}
__attribute__((always_inline)) bool is_vec_watchpoint_set(irq_val irq,hw_addr addr)
{
    return models[irq]->vec_watchpoints->find(addr) != models[irq]->vec_watchpoints->end();
}
__attribute__((always_inline)) void set_vec_watchpoint(irq_val irq,hw_addr addr)
{
    insert_nostop_watchpoint(addr,4,QEMU_PLUGIN_MEM_W_ ,nostop_watchpoint_exec_overwrite_vec,(void*)(uint64_t)irq);
    models[irq]->vec_watchpoints->insert(addr);
}


void set_state(IRQ_N_STATE *state,irq_val irq)
{
    for(auto it = state->func_nullptr->begin() ; it!= state->func_nullptr->end(); it++)
    {
        it->second->point = insert_nostop_watchpoint(it->first,4,QEMU_PLUGIN_MEM_W_ ,nostop_watchpoint_exec_unresolved_func_ptr,(void*)(uint64_t)irq);   
    }
    if(!state->toend)
        return;
    for(auto it = state->mem_addr->begin() ; it!= state->mem_addr->end(); it++)
    {
        it->second->point = insert_nostop_watchpoint(it->first,4,QEMU_PLUGIN_MEM_R_ ,nostop_watchpoint_exec_mem,(void*)(uint64_t)irq);
    }
    
    
    state->mem_access_trigger_irq_times_count = 0;
}
void clear_state(IRQ_N_STATE *state)
{
    for(auto it = state->mem_addr->begin() ; it!= state->mem_addr->end(); it++)
    {
        if(it->second->point)
        {
            delete_nostop_watchpoint(it->second->point);
            it->second->point = 0;
        }   
    }
    for(auto it = state->func_nullptr->begin() ; it!= state->func_nullptr->end(); it++)
    {
        if(it->second->point)
        {
            delete_nostop_watchpoint(it->second->point);
            it->second->point = 0;
        }
            
    }
}

__attribute__((always_inline)) bool is_irq_ready(IRQ_N_STATE *state)
{
    
    set<void*> *dependency_nullptr = state->dependency_nullptr;
    
    for(auto it = dependency_nullptr->begin(); it != dependency_nullptr->end(); it++)
    {
        if(*(uint32_t*)(*it) == 0)
            return false;
    }
    return true;
}
__attribute__((always_inline)) bool is_irq_access_memory(IRQ_N_STATE *state)
{
    return state->mem_addr->size() != 0 ;
}


void switch_state(hw_addr old_id,hw_addr new_id, hw_addr new_isr, irq_val irq)
{
    if (old_id == new_id)
        return;
    IRQ_N_STATE *old_state = (*models[irq]->state)[old_id];
    clear_state(old_state);
    
    IRQ_N_STATE *new_state = (*models[irq]->state)[new_id];
    set_state(new_state,irq);

    models[irq]->current_isr = new_isr;
    models[irq]->current_id = new_id;

    #ifdef DBG
    fprintf(flog,"%d->irq %d switch from %x to %x\n",run_index,irq,old_id,new_id);
    #endif
}

void irq_set_isr(irq_val irq, hw_addr vec_addr)
{
    hw_addr isr;
    hw_addr current_id = get_current_id(irq);
        
    if (vec_addr != INVALID_VECADDR)
        read_ram(vec_addr,sizeof(isr),&isr);
    else
        isr = 0;
    
    if (vec_addr != INVALID_VECADDR && !is_vec_watchpoint_set(irq,vec_addr))
        set_vec_watchpoint(irq,vec_addr);

    if(!is_isr_modeled(irq,isr))
    {
        dump_prcoess_load_model(irq,isr,isr, &models);
    }

    switch_state(current_id,isr,isr, irq);  
}
hw_addr get_current_vec_addr(irq_val irq)
{
    return get_nvic_vecbase() + 4 * irq;
}


void irq_on_set_new_vecbase(hw_addr addr)
{
    #ifdef DBG
    fprintf(flog,"%d->set vecbase %x\n",run_index,addr);
    #endif
    for(auto it = models.begin(); it != models.end(); it++)
    {
        if(!it->second->enabled)
            continue;
        irq_set_isr(it->first,get_current_vec_addr(it->first));
    }
}

void irq_on_overwrite_vec_entry(irq_val irq,hw_addr vaddr)
{
    irq_set_isr(irq,vaddr);
}

void irq_on_enable_nvic_irq(int irq)
{
    #ifdef DBG
    fprintf(flog,"%d->enable irq %d\n",run_index,irq);
    #endif
    models[irq]->enabled = true;
    enabled_irqs.insert(irq);
    irq_set_isr(irq,get_current_vec_addr(irq));
    
}
void irq_on_disable_nvic_irq(int irq)
{
    
    if(models[irq]->enabled)
    {
        #ifdef DBG
        fprintf(flog,"%d->disable irq %d\n",run_index,irq);
        #endif
        models[irq]->enabled = false;
        enabled_irqs.erase(irq);
        irq_set_isr(irq, INVALID_VECADDR);
    }
    
}
void irq_on_new_run()
{
    set<irq_val> tmp(enabled_irqs);
    for(auto it = tmp.begin(); it != tmp.end(); it++)
    {
        irq_on_disable_nvic_irq(*it);
    }
    irq_on_enable_nvic_irq(ARMV7M_EXCP_SYSTICK);
    idle_count = 1;
}
void irq_on_init()
{
    char model_filename[PATH_MAX];
    sprintf(model_filename,"%s/%s",model_dir.c_str(),IRQ_MODEL_FILENAME);

    for(int irq = ARMV7M_EXCP_SYSTICK; irq < MAX_NVIC_IRQ; irq ++)
    {
        models[irq] = new IRQ_N_MODEL();
        models[irq]->enabled = false;
        models[irq]->current_isr = 0;
        models[irq]->current_id = 0;
        models[irq]->state = new map<hw_addr,IRQ_N_STATE*>();
        (*models[irq]->state)[models[irq]->current_id] = get_void_state();
        models[irq]->vec_watchpoints = new set<hw_addr>();
    }

    if (access(model_filename, F_OK) == 0) 
    {
        // remove(model_filename);
        load_model(model_filename, &models);
    }

}




void irq_on_mem_access(int irq,hw_addr addr)
{

    bool insert_irq;

    if(get_arm_v7m_is_handler_mode() != 0)
        return;
        
    IRQ_N_STATE *state = (*models[irq]->state)[get_current_id(irq)];
    if(!is_irq_ready(state))
        return;

    

    state->mem_access_trigger_irq_times_count++;
    if(state->mem_access_trigger_irq_times_count > (state->mem_addr->size() << 5))
    {
        insert_irq = insert_nvic_intc(irq);
        state->mem_access_trigger_irq_times_count = 0;
        if(insert_irq) 
        {
            #ifdef DBG
            fprintf(flog,"%d->insert mem access irq %d\n",run_index,irq);
            #endif
        }
    }
}


void irq_on_idel()
{   
    
    if(
       get_arm_v7m_is_handler_mode() != ARMV7M_EXCP_PENDSV && 
       get_arm_v7m_is_handler_mode() != ARMV7M_EXCP_SVC && 
       get_arm_v7m_is_handler_mode() != 0)
        return;

    if((idle_count & 7) != 0)
    {
        idle_count++;
        return;
    }
    idle_count++;
    
    for(auto it = enabled_irqs.begin(); it != enabled_irqs.end(); it++)
    {
        irq_val irq = *it;

        IRQ_N_STATE *state = (*models[irq]->state)[get_current_id(irq)];
        if(!is_irq_access_memory(state))
            continue;
        if(!state->toend)
            continue;
        if(!is_irq_ready(state))
            continue;
       
        
        bool insert_irq = insert_nvic_intc(irq);
        #ifdef DBG
        
        if(insert_irq)
            fprintf(flog,"%d->insert idel irq %d\n",run_index,irq);
        #endif
    }
   
    
}
void irq_on_unsolved_func_ptr_write(int irq, uint32_t addr, uint32_t val)
{
    if(val == 0)
        return;
    if(!models[irq]->enabled)
        return;
    IRQ_N_STATE *state = (*models[irq]->state)[get_current_id(irq)];
    if(state->func_resolved_ptrs->find(val) == state->func_resolved_ptrs->end())
    {
        dump_prcoess_load_model(irq, get_current_id(irq) ^ val,get_current_isr(irq),&models);
        state->func_resolved_ptrs->insert(val);
    }

}

