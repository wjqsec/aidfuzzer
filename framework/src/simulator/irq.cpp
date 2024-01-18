#include <map>
#include <vector>
#include <set>
#include <algorithm>
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


IRQ_N_MODEL* models[MAX_NVIC_IRQ];

vector<irq_val> enabled_irqs;
uint64_t idle_count = 0;

map<irq_val,uint32_t> snapshot_enabled_irq;

IRQ_N_STATE *get_void_state()
{
    IRQ_N_STATE* state = new IRQ_N_STATE();
    state->isr = 0;
    state->toend = false;
    state->mem_access_trigger_irq_times_count = new map<hw_addr,int>();
    state->mem_addr = new map<hw_addr,WATCHPOINT*>();
    state->dependency_nullptr = new set<void*>();
    state->func_nullptr = new map<hw_addr,WATCHPOINT*>();
    state->func_resolved_ptrs = new map<hw_addr,hw_addr>();
    return state;
}

__attribute__((always_inline)) hw_addr get_current_id(irq_val irq)
{
    return models[irq]->current_id;
}

__attribute__((always_inline)) hw_addr get_current_isr(irq_val irq)
{
    return (*models[irq]->state)[get_current_id(irq)]->isr;
}
__attribute__((always_inline)) bool is_id_modeled(irq_val irq,hw_addr id)
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

__attribute__((always_inline)) void reset_irq_mem_access(IRQ_N_STATE *state)
{
    for(auto it = state->mem_access_trigger_irq_times_count->begin(); it != state->mem_access_trigger_irq_times_count->end(); it++)
    {
        it->second = 0;
    }
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
    
    
    reset_irq_mem_access(state);
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


void switch_state(hw_addr old_id,hw_addr new_id, irq_val irq)
{
    if (old_id == new_id)
        return;
    IRQ_N_STATE *old_state = (*models[irq]->state)[old_id];
    clear_state(old_state);
    
    IRQ_N_STATE *new_state = (*models[irq]->state)[new_id];
    set_state(new_state,irq);

    models[irq]->current_id = new_id;

    #ifdef DBG
    fprintf(flog,"%d->irq %d switch from %x to %x\n",run_index,irq,old_id,new_id);
    #endif
}

void irq_set_isr(irq_val irq, hw_addr vec_addr)
{
    hw_addr isr;
    hw_addr current_id = get_current_id(irq);
    hw_addr new_id;
        
    if (vec_addr != INVALID_VECADDR)
        read_ram(vec_addr,sizeof(isr),&isr);
    else
        isr = 0;
    new_id = isr;
    if (vec_addr != INVALID_VECADDR && !is_vec_watchpoint_set(irq,vec_addr))
        set_vec_watchpoint(irq,vec_addr);

    if(!is_id_modeled(irq,new_id))
    {
        dump_prcoess_load_model(irq,new_id,isr, models);
    }

    if(models[irq]->state->find(new_id) == models[irq]->state->end())
    {
        printf("unable to find irq model for id %x\n",isr);
        terminate_simulation();
    }

    switch_state(current_id,new_id, irq);  

    IRQ_N_STATE *new_state = (*models[irq]->state)[new_id];

    for(auto it = new_state->func_nullptr->begin(); it != new_state->func_nullptr->end(); it++)
    {
        hw_addr addr = it->first;
        uint32_t val;
        read_ram(addr,4,&val);   
        irq_on_unsolved_func_ptr_write(irq, addr, val);
    }

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
    for(int i = 0 ; i < MAX_NVIC_IRQ ; i++)
    {
        if(!models[i]->enabled)
            continue;
        irq_set_isr(i,get_current_vec_addr(i));
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
    enabled_irqs.push_back(irq);
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
        enabled_irqs.erase(std::remove(enabled_irqs.begin(), enabled_irqs.end(), irq), enabled_irqs.end());

        irq_set_isr(irq, INVALID_VECADDR);
    }
    
}

void irq_on_new_run()
{
    #ifdef DBG
        fprintf(flog,"%d->irq new run\n",run_index);
    #endif
    vector<irq_val> tmp(enabled_irqs);
    for(auto it = tmp.begin(); it != tmp.end(); it++)
    {
        irq_on_disable_nvic_irq(*it);
    }
    
    idle_count = 0;
    for(auto it = snapshot_enabled_irq.begin(); it != snapshot_enabled_irq.end(); it++)
    {
        models[it->first]->enabled = true;
        enabled_irqs.push_back(it->first);
        switch_state(0,it->second, it->first);
    }
}
void irq_on_snapshot()
{
    for(int i = 0 ; i < MAX_NVIC_IRQ ; i++)
    {
        if(!models[i]->enabled)
            continue;
        snapshot_enabled_irq[i] = get_current_id(i);
    }
}
void irq_on_init()
{
    char model_filename[PATH_MAX];
    sprintf(model_filename,"%s/%s",model_dir.c_str(),IRQ_MODEL_FILENAME);

    for(int irq = 0; irq < MAX_NVIC_IRQ; irq ++)
    {
        models[irq] = new IRQ_N_MODEL();
        models[irq]->enabled = false;
        models[irq]->current_id = 0;
        models[irq]->state = new map<hw_addr,IRQ_N_STATE*>();
        (*models[irq]->state)[models[irq]->current_id] = get_void_state();
        models[irq]->vec_watchpoints = new set<hw_addr>();
    }

    if (access(model_filename, F_OK) == 0) 
    {
        load_model(model_filename, models);
    }
    irq_on_enable_nvic_irq(ARMV7M_EXCP_SYSTICK);

}




void irq_on_mem_access(int irq,hw_addr addr)
{

    bool insert_irq;

    if(get_arm_v7m_is_handler_mode() != 0)
        return;
        
    IRQ_N_STATE *state = (*models[irq]->state)[get_current_id(irq)];
    if(!is_irq_ready(state))
        return;

    

    (*state->mem_access_trigger_irq_times_count)[addr] ++;
    if((*state->mem_access_trigger_irq_times_count)[addr] > NUM_IRQ_MEM_ACCESS_TIMES)
    {
        insert_irq = insert_nvic_intc(irq);
        reset_irq_mem_access(state);
        if(insert_irq) 
        {
            #ifdef DBG
            fprintf(flog,"%d->insert mem access irq %d\n",run_index,irq);
            #endif
        }
    }
}


void irq_on_idel(int skip_count)
{   
    int irq;
    
    if (skip_count)
    {
        idle_count++;
        if (idle_count <= skip_count)
        {
            return;
        }
    }
    if(get_arm_v7m_is_handler_mode() != 0)
        return;
    idle_count = 0;    
    for(int i = 0 ; i < enabled_irqs.size(); i++)
    {
        irq = enabled_irqs[i];
        IRQ_N_STATE *state = (*models[irq]->state)[get_current_id(irq)];
        if(!is_irq_access_memory(state))
            continue;
            

        if(!state->toend)
            continue;

        if(!is_irq_ready(state))
            continue;
        bool insert_irq = insert_nvic_intc(irq);
        
        if(insert_irq)
        {
            reset_irq_mem_access(state);
            #ifdef DBG
        
        
            fprintf(flog,"%d->insert idel irq %d\n",run_index,irq);
            #endif
        }
        
        // break;
    }
}


void irq_on_unsolved_func_ptr_write(int irq, uint32_t addr, uint32_t val)
{
    if(val == 0)
        return;
    if(get_arm_v7m_is_handler_mode() != 0)
        return;
    u32 isr = get_current_isr(irq);
    u32 old_id = get_current_id(irq);
    
    IRQ_N_STATE *old_state = (*models[irq]->state)[old_id];

    u32 new_id = isr;

    map<hw_addr,hw_addr> tmp_func_resolved_ptrs(*old_state->func_resolved_ptrs);
    tmp_func_resolved_ptrs[addr] = val;

    for(auto it = tmp_func_resolved_ptrs.begin(); it != tmp_func_resolved_ptrs.end(); it++)
    {
        new_id ^= hash_32_ext(it->second);
    }

    if(models[irq]->state->find(new_id) == models[irq]->state->end())
    {
        printf("resolved irq %d addr %x value %x\n",irq,addr,val);
        dump_prcoess_load_model(irq, new_id ,isr , models);
    }

    if(models[irq]->state->find(new_id) == models[irq]->state->end())
    {
        printf("unable to find irq model for id %x\n",new_id);
        terminate_simulation();
    }

    IRQ_N_STATE *new_state = (*models[irq]->state)[new_id];

    new_state->func_resolved_ptrs->clear();
    new_state->func_resolved_ptrs->insert(tmp_func_resolved_ptrs.begin(), tmp_func_resolved_ptrs.end());

    IRQ_N_STATE *init_state = (*models[irq]->state)[isr];

    for(auto it = init_state->func_nullptr->begin(); it != init_state->func_nullptr->end(); it++)
    {
        if(new_state->func_nullptr->find(it->first) == new_state->func_nullptr->end())
        {
            WATCHPOINT *watchpoint = new WATCHPOINT();
            watchpoint->addr = it->first;
            watchpoint->point = 0;
            (*new_state->func_nullptr)[it->first] = watchpoint;
        }
    }
    
    
    

    switch_state(old_id,new_id, irq);

}

