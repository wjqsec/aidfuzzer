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
hw_addr get_current_isr(irq_val irq)
{
    return models[irq]->current_isr;
}
bool is_isr_modeled(irq_val irq,hw_addr isr)
{
    return models[irq]->state->find(isr) != models[irq]->state->end();
}
bool is_vec_watchpoint_set(irq_val irq,hw_addr addr)
{
    return models[irq]->vec_watchpoints->find(addr) != models[irq]->vec_watchpoints->end();
}
void set_vec_watchpoint(irq_val irq,hw_addr addr)
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


__attribute__((always_inline)) bool is_irq_ready(irq_val irq)
{
    
    if(!models[irq]->enabled)
        return false;
    
    if(!(*models[irq]->state)[get_current_isr(irq)]->toend)
        return false;
    
    set<void*> *dependency_nullptr = (*models[irq]->state)[get_current_isr(irq)]->dependency_nullptr;
    
    for(auto it = dependency_nullptr->begin(); it != dependency_nullptr->end(); it++)
    {
        if(*(uint32_t*)(*it) == 0)
            return false;
    }
    return true;
}
__attribute__((always_inline)) bool is_irq_access_memory(irq_val irq)
{
    int num_mem = (*models[irq]->state)[get_current_isr(irq)]->mem_addr->size();
    
    return num_mem != 0 ;
}



void irq_set_isr(irq_val irq, hw_addr vec_addr)
{
    hw_addr isr;
    hw_addr current_isr = get_current_isr(irq);
        
    if (vec_addr != INVALID_VECADDR)
        read_ram(vec_addr,sizeof(isr),&isr);
    else
        isr = 0;
    
    if (vec_addr != INVALID_VECADDR && !is_vec_watchpoint_set(irq,vec_addr))
        set_vec_watchpoint(irq,vec_addr);

    if(!is_isr_modeled(irq,isr))
    {
        dump_prcoess_load_model(irq,isr, &models);
    }
        
    if (current_isr == isr)
        return;

    IRQ_N_STATE *old_state = (*models[irq]->state)[current_isr];
    clear_state(old_state);
    
    IRQ_N_STATE *new_state = (*models[irq]->state)[isr];
    set_state(new_state,irq);

    models[irq]->current_isr = isr;
    #ifdef DBG
    fprintf(flog,"%d->irq %d switch from %x to %x\n",run_index,irq,current_isr,isr);
    #endif
    
    
    
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
    for(auto it = models.begin(); it != models.end(); it++)
    {
        irq_on_disable_nvic_irq(it->first);
    }
    irq_on_enable_nvic_irq(ARMV7M_EXCP_SYSTICK);
    idle_count = 1;
}
void irq_on_init()
{
    char model_filename[PATH_MAX];
    sprintf(model_filename,"%s/%s",model_dir,IRQ_MODEL_FILENAME);

    for(int irq = ARMV7M_EXCP_SYSTICK; irq < MAX_NVIC_IRQ; irq ++)
    {
        models[irq] = new IRQ_N_MODEL();
        models[irq]->enabled = false;
        models[irq]->current_isr = 0;
        models[irq]->state = new map<hw_addr,IRQ_N_STATE*>();
        (*models[irq]->state)[models[irq]->current_isr] = get_void_state();
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
    if(!is_irq_access_memory(irq))
            return;
    if(!is_irq_ready(irq))
        return;

    IRQ_N_STATE *state = (*models[irq]->state)[get_current_isr(irq)];

    state->mem_access_trigger_irq_times_count++;
    if(state->mem_access_trigger_irq_times_count > (state->mem_addr->size() * 7))
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
        if(!is_irq_access_memory(irq))
            continue;
       
        if(!is_irq_ready(irq))
        {
            continue;
        }
       
        
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
    IRQ_N_STATE *state = (*models[irq]->state)[get_current_isr(irq)];
    if(state->func_resolved_ptrs->find(val) == state->func_resolved_ptrs->end())
    {
        
        dump_prcoess_load_model(irq,get_current_isr(irq),&models);
        
        state->func_resolved_ptrs->insert(val);
    }

}

