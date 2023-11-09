#include <map>
#include <vector>
#include <set>
#include "irq.h"

#include "utl.h"
#include "model.h"
#include "simulator.h"
#include <stdio.h>

using namespace std;
#define INVALID_VECADDR 0xffffffff
#define MAX_NVIC_IRQ 250



struct WATCHPOINT
{
    NOSTOP_WATCHPOINT *point;
    hw_addr addr;
};

struct IRQ_N_STATIC_STATE 
{
    map<hw_addr,WATCHPOINT*> *mem_addr;
    set<hw_addr> *dependency_nullptr;
    map<hw_addr,WATCHPOINT*> *func_nullptr;
    set<hw_addr> *func_resolved_ptrs;
};

struct IRQ_N_RUNTIME_STATE 
{
    int mem_access_trigger_irq_times_count;
};


struct IRQ_N_STATE
{
    IRQ_N_STATIC_STATE static_state;
    IRQ_N_RUNTIME_STATE runtime_state;
};


struct IRQ_N_MODEL
{
    bool enabled;
    hw_addr current_isr;
    set<hw_addr> *vec_watchpoints;
    map<hw_addr,IRQ_N_STATE*> *state;
};


map<irq_val,IRQ_N_MODEL*> models;
set<irq_val> enabled_irqs;


IRQ_N_STATE *get_void_state()
{
    IRQ_N_STATE* state = new IRQ_N_STATE();
    state->static_state.mem_addr = new map<hw_addr,WATCHPOINT*>();
    state->static_state.dependency_nullptr = new set<hw_addr>();
    state->static_state.func_nullptr = new map<hw_addr,WATCHPOINT*>();
    state->static_state.func_resolved_ptrs = new set<hw_addr>();
    state->runtime_state.mem_access_trigger_irq_times_count = 0;
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
    
    for(auto it = state->static_state.mem_addr->begin() ; it!= state->static_state.mem_addr->end(); it++)
    {
        it->second->point = insert_nostop_watchpoint(it->first,4,QEMU_PLUGIN_MEM_R_ ,nostop_watchpoint_exec_mem,(void*)(uint64_t)irq);
    }
    for(auto it = state->static_state.func_nullptr->begin() ; it!= state->static_state.func_nullptr->end(); it++)
    {
        it->second->point = insert_nostop_watchpoint(it->first,4,QEMU_PLUGIN_MEM_W_ ,nostop_watchpoint_exec_unresolved_func_ptr,(void*)(uint64_t)irq);   
    }
    
    state->runtime_state.mem_access_trigger_irq_times_count = 0;
}
void clear_state(IRQ_N_STATE *state)
{
    for(auto it = state->static_state.mem_addr->begin() ; it!= state->static_state.mem_addr->end(); it++)
    {
        if(it->second->point)
        {
            delete_nostop_watchpoint(it->second->point);
            it->second->point = 0;
        }   
    }
    for(auto it = state->static_state.func_nullptr->begin() ; it!= state->static_state.func_nullptr->end(); it++)
    {
        if(it->second->point)
        {
            delete_nostop_watchpoint(it->second->point);
            it->second->point = 0;
        }
            
    }
}


bool is_irq_ready(irq_val irq)
{
    set<hw_addr> *dependency_nullptr = (*models[irq]->state)[get_current_isr(irq)]->static_state.dependency_nullptr;
    // printf("is_irq_ready %d current isr %x %d\n",irq,get_current_isr(irq),dependency_nullptr->size());
    uint32_t val;
    for(auto it = dependency_nullptr->begin(); it != dependency_nullptr->end(); it++)
    {
        read_ram(*it,4,&val);
        if(val == 0)
            return  false;
    }
    return true;
}
bool is_irq_access_memory(irq_val irq)
{
    int num_mem = (*models[irq]->state)[get_current_isr(irq)]->static_state.mem_addr->size();
    // printf("is_irq_access_memory irq %d current isr %x  %d\n",irq,get_current_isr(irq),num_mem);
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
        (*models[irq]->state)[isr] = get_void_state();
        model_dumped_irq(irq,isr);
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
void irq_on_overwrite_vec_entry(irq_val irq,hw_addr vaddr)
{
    
    if(models[irq]->enabled)
    {
        #ifdef DBG
        fprintf(flog,"%d->overwrite irq %d addr %x\n",run_index,irq,vaddr);
        #endif
        irq_set_isr(irq, vaddr);
    }
        
}

void irq_on_set_new_vecbase(hw_addr addr)
{
    #ifdef DBG
    fprintf(flog,"%d->set vecbase %x\n",run_index,addr);
    #endif
    for(auto it = models.begin(); it != models.end(); it++)
    {
        irq_on_overwrite_vec_entry(it->first,get_current_vec_addr(it->first));
    }
}



void irq_on_enable_nvic_irq(int irq)
{
    #ifdef DBG
    fprintf(flog,"%d->enable irq %d\n",run_index,irq);
    #endif
    models[irq]->enabled = true;
    enabled_irqs.insert(irq);
    irq_on_overwrite_vec_entry(irq,get_current_vec_addr(irq));
    
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
}
void irq_on_init()
{
    char cmd[PATH_MAX];
    sprintf(cmd,"rm %s/%s",model_dir,IRQ_MODEL_FILENAME);
    system(cmd);

    for(int irq = ARMV7M_EXCP_SYSTICK; irq < MAX_NVIC_IRQ; irq ++)
    {

        models[irq] = new IRQ_N_MODEL();
        models[irq]->enabled = false;
        models[irq]->current_isr = 0;
        models[irq]->state = new map<hw_addr,IRQ_N_STATE*>();

        (*models[irq]->state)[0] = get_void_state();

        models[irq]->vec_watchpoints = new set<hw_addr>();

        
    }

}




void irq_on_mem_access(int irq,hw_addr addr)
{

    bool insert_irq;

    if(get_arm_v7m_is_handler_mode() != 0)
        return;

    if(!is_irq_ready(irq))
        return;

    IRQ_N_RUNTIME_STATE *runtime_state = &((*models[irq]->state)[get_current_isr(irq)]->runtime_state);
    IRQ_N_STATIC_STATE *static_state = &((*models[irq]->state)[get_current_isr(irq)]->static_state);

    runtime_state->mem_access_trigger_irq_times_count++;
    if(runtime_state->mem_access_trigger_irq_times_count > static_state->mem_addr->size())
    {
        insert_irq = insert_nvic_intc(irq);
        runtime_state->mem_access_trigger_irq_times_count = 0;
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
    static uint64_t count = 0;
    // static int irq = ARMV7M_EXCP_SYSTICK;
    // #ifdef DBG
    //     fprintf(flog,"%d->try insert idel is_handler_mode:%d num_enabled_irqs:%d ready:",run_index,get_arm_v7m_is_handler_mode(),irq_model.num_enabled_irqs);
    //     for(int i = 0; i < irq_model.num_enabled_irqs; i++)
    //     {
    //         if( is_irq_access_memory(irq_model.enabled_irqs[i]))
    //         {
    //             fprintf(flog,"%d  ",irq_model.enabled_irqs[i]);
    //         }
    //     }
    //     fprintf(flog,"\n");
    // #endif
    
    if(
       get_arm_v7m_is_handler_mode() != ARMV7M_EXCP_PENDSV && 
       get_arm_v7m_is_handler_mode() != ARMV7M_EXCP_SVC && 
       get_arm_v7m_is_handler_mode() != 0)
        return;

    if((count & 7) != 0)
    {
        count++;
        return;
    }
    count++;
    for(auto it = enabled_irqs.begin(); it != enabled_irqs.end(); it++)
    {
        irq_val irq = *it;
        bool con1 = is_irq_ready(irq);
        bool con2 = is_irq_access_memory(irq);
        
        // printf("try insert %d %d  %d\n", irq, con1, con2);
        if(
            con1 && con2
        )
        {
            bool insert_irq = insert_nvic_intc(irq);
            #ifdef DBG
            if(insert_irq)
                fprintf(flog,"%d->insert idel irq %d\n",run_index,irq);
            #endif
        }
    }
    
}
void irq_on_unsolved_func_ptr_write(int irq, uint32_t addr, uint32_t val)
{
    if(val == 0)
        return;
    IRQ_N_STATIC_STATE *static_state = &((*models[irq]->state)[get_current_isr(irq)]->static_state);
    if(static_state->func_resolved_ptrs->find(val) == static_state->func_resolved_ptrs->end())
    {
        model_dumped_irq(irq,get_current_isr(irq));
        static_state->func_resolved_ptrs->insert(val);
    }

}


void add_memory_access_watchpoint(int irq, uint32_t addr, hw_addr isr)
{
    IRQ_N_STATIC_STATE *static_state = &((*models[irq]->state)[isr]->static_state);
    if(static_state->mem_addr->find(addr) == static_state->mem_addr->end())
    {
        WATCHPOINT *watchpoint = new WATCHPOINT();
        watchpoint->addr = addr;
        watchpoint->point = 0;
        (*static_state->mem_addr)[addr] = watchpoint;
        printf("add memory access watchpoint irq %d addr %x\n",irq,addr);
    }
    
}
void add_unsolved_func_ptr(int irq, uint32_t addr, hw_addr isr)
{
    IRQ_N_STATIC_STATE *static_state = &((*models[irq]->state)[isr]->static_state);
    if(static_state->func_nullptr->find(addr) == static_state->func_nullptr->end())
    {
        WATCHPOINT *watchpoint = new WATCHPOINT();
        watchpoint->addr = addr;
        watchpoint->point = 0;
        (*static_state->mem_addr)[addr] = watchpoint;
        printf("add unsolved func ptr irq %d addr %x\n",irq,addr);
    }
    
}
void add_dependency_func_ptr(int irq,uint32_t addr, hw_addr isr)
{
    (*models[irq]->state)[isr]->static_state.dependency_nullptr->insert(addr);
    printf("add dependency ptr irq %d addr %x\n",irq,addr);
}