
#include "xx.h"
#include "kk_ihex.h"
#include "simulator.h"
#include <stdio.h>
#include <stdint.h>
#include <limits.h>
#include <unistd.h>
#include <kk_ihex_write.h>
#include "irq.h"
#include "model.h"
#define STOPWATCH_TYPE_MMIO 0
#define STOPWATCH_TYPE_MEM 1
#define STOPWATCH_TYPE_FUNC_POINTER 2
#define STOPWATCH_TYPE_DEPENDENCY 3











FILE *state_file;
void ihex_flush_buffer(struct ihex_state *ihex,char *buffer, char *eptr)
{
    *eptr = '\0';
    fputs(buffer,state_file);
}

char* dump_state(uint32_t mmio_id, const char * prefix, const char *dir)
{
    int i;
    uint8_t *buf;
    char state_filename[PATH_MAX];
    ARM_CPU_STATE state;
    struct ihex_state ihex;

    

    get_arm_cpu_state(&state);
    sprintf(state_filename,"%s/%s%08x",dir,prefix,mmio_id);
    state_file = fopen(state_filename,"w");
    fprintf(state_file, "r0=0x%08x\n"
                        "r1=0x%08x\n"
                        "r2=0x%08x\n"
                        "r3=0x%08x\n"
                        "r4=0x%08x\n"
                        "r5=0x%08x\n"
                        "r6=0x%08x\n"
                        "r7=0x%08x\n"
                        "r8=0x%08x\n"
                        "r9=0x%08x\n"
                        "r10=0x%08x\n"
                        "r11=0x%08x\n"
                        "r12=0x%08x\n"
                        "lr=0x%08x\n"
                        "pc=0x%08x\n"
                        "sp=0x%08x\n"
                        "xpsr=0x%08x\n",
        state.regs[0],
        state.regs[1],
        state.regs[2],
        state.regs[3],
        state.regs[4],
        state.regs[5],
        state.regs[6],
        state.regs[7],
        state.regs[8],
        state.regs[9],
        state.regs[10],
        state.regs[11],
        state.regs[12],
        state.regs[14],
        (uint32_t)get_arm_precise_pc(),
        state.regs[13],
        state.xpsr
    );
    ihex_init(&ihex);
    for(auto it = config->segs->begin(); it != config->segs->end(); it++)
    {
        if((*it)->type == SEG_RAM)
        {
            buf = (uint8_t *)malloc((*it)->size);
            memcpy(buf,(*it)->ptr,(*it)->size);
            ihex_write_at_address(&ihex, (*it)->start);
            ihex_write_bytes(&ihex, buf, (*it)->size);
            free(buf);
        }
        
    }

    ihex_end_write(&ihex);

    fclose(state_file);
    return strdup(state_filename);

}
void model_all_infinite_loop()
{
    FILE *f;
    char *state_filename;
    char model_filename[PATH_MAX];
    char line[PATH_MAX];
    char cmd[PATH_MAX];
    sprintf(model_filename,"%s/%s",model_dir.c_str(),LOOP_MODEL_FILENAME);

    
    if(access(model_filename,F_OK) != 0)
    {
        state_filename = dump_state(0,LOOP_STATE_PREFIX,dump_dir.c_str());
        sprintf(cmd,"python3  ../../script/dataflow_modelling/infinite_loop.py -s %s -o %s -c %s > /dev/null 2>&1",state_filename,model_filename,fuzzware_config_filename.c_str());
        puts(cmd);
        system(cmd);
        free(state_filename);
    }
    
    
    f = fopen(model_filename,"r");
    if(f)
    {
        while(fgets(line, PATH_MAX, f))
        {
            uint32_t addr = strtol(line,0,16);
            if(addr)
            {
                register_exec_specific_bbl_hook(addr,arm_exec_loop_bbl);
                printf("register_exec_specific_bbl_hook %x\n",addr);
            }
                 
        }
        fclose(f);
    }
    else
    {
        printf("model file %s not found,exit\n",model_filename);
        terminate_simulation();
    }
}

void load_model(char *model_filename, IRQ_N_MODEL **models)
{
    char line[PATH_MAX];
    FILE *f = fopen(model_filename,"r");
    if(!f)
    {
        printf("model file %s not found,exit\n",model_filename);
        terminate_simulation();
    }

    int type;
    bool to_end;
    int irq;
    uint32_t isr;
    uint32_t id;
    char *addr_size_ptr;
    IRQ_N_MODEL *model;
    IRQ_N_STATE *state;


    while(fgets(line, PATH_MAX, f))
    {
        if(strstr(line,"-"))
        {
            irq = strtol(strstr(line,"-") + 1,0,10);
            model = models[irq];
            id = strtol(strstr(strstr(line,"-") + 1, "-") + 1,0,16);
            isr = strtol(strstr(strstr(strstr(line,"-") + 1, "-") + 1 , "-") + 1 , 0 , 16);
            if (model->state->find(id) == model->state->end())
            {
                (*model->state)[id] = get_void_state();
                printf("log irq %d\n",irq);
            }
            else
            {
                continue;
            }
            state = (*model->state)[id];
            if(strstr(line,"y"))
                state->toend = true;
            else
            {
                state->toend = false;   
            }
            state->isr = isr;
        }
        else
        {
            if(strstr(line,"mem:"))
            {
                type = STOPWATCH_TYPE_MEM;
                addr_size_ptr = line + strlen("mem:");
            }
            else if(strstr(line,"mmio:"))
            {
                type = STOPWATCH_TYPE_MMIO;
                addr_size_ptr = line + strlen("mmio:");
            }
            else if(strstr(line,"func:"))
            {
                type = STOPWATCH_TYPE_FUNC_POINTER;
                addr_size_ptr = line + strlen("func:");
            }
            else if(strstr(line,"dependency:"))
            {
                type = STOPWATCH_TYPE_DEPENDENCY;
                addr_size_ptr = line + strlen("dependency:");
            }

            uint32_t addr = strtol(addr_size_ptr, 0, 16);
            uint32_t len = strtol(strstr(addr_size_ptr," ") + 1, 0, 16);

            if(type == STOPWATCH_TYPE_MEM)
            {
                if(state->mem_addr->find(addr) == state->mem_addr->end())
                {
                    WATCHPOINT *watchpoint = new WATCHPOINT();
                    watchpoint->addr = addr;
                    watchpoint->point = 0;
                    (*state->mem_addr)[addr] = watchpoint;
                    printf("add memory access watchpoint irq %d addr %x\n",irq,addr);
                }
                
            }
            else if(type == STOPWATCH_TYPE_MMIO)
            {
                        
            }
            else if(type == STOPWATCH_TYPE_FUNC_POINTER)
            {
                if(state->func_nullptr->find(addr) == state->func_nullptr->end())
                {
                    WATCHPOINT *watchpoint = new WATCHPOINT();
                    watchpoint->addr = addr;
                    watchpoint->point = 0;
                    (*state->func_nullptr)[addr] = watchpoint;
                    printf("add unsolved func ptr irq %d addr %x\n",irq,addr);
                }
            }
            else if(type == STOPWATCH_TYPE_DEPENDENCY)
            {
                void *ramptr = get_ram_ptr(addr);
                if(state->dependency_nullptr->find(ramptr) == state->dependency_nullptr->end())
                {
                    state->dependency_nullptr->insert(ramptr);
                    printf("add dependency ptr irq %d addr %x\n",irq,addr);
                }
                
            }
        }
    }

    fclose(f);
    
}


void dump_prcoess_load_model(int irq,hw_addr id ,hw_addr isr, IRQ_N_MODEL **models)
{
    char *state_filename;
    char model_filename[PATH_MAX];
    char cmd[PATH_MAX];
    
    sprintf(model_filename,"%s/%s",model_dir.c_str(),IRQ_MODEL_FILENAME);

    state_filename = dump_state(id,IRQ_STATE_PREFIX,dump_dir.c_str());

    sprintf(cmd,"pc: %x  irq_entry: %x   ",(uint32_t)get_arm_pc(),isr);
    printf("%s",cmd);
    fprintf(f_irq_log,"%s",cmd);

    sprintf(cmd,"python3 ../../script/dataflow_modelling/irq_model.py -s %s -v 0x%x -i %d -d 0x%x -o %s -c %s > /dev/null 2>&1",state_filename,get_nvic_vecbase(), irq, id, model_filename,fuzzware_config_filename.c_str());
    puts(cmd);

    fprintf(f_irq_log,"%s\n",cmd);
    system(cmd);
    free(state_filename);

    load_model(model_filename, models);

}