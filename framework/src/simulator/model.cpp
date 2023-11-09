#include "model.h"
#include "xx.h"
#include "kk_ihex.h"
#include "simulator.h"
#include <stdio.h>
#include <stdint.h>
#include <limits.h>
#include <unistd.h>
#include <kk_ihex_write.h>
#include "irq.h"
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

char* dump_state(uint32_t mmio_id, const char * prefix, char *dir)
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
            read_ram((*it)->start,(*it)->size,buf);
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
    sprintf(model_filename,"%s/%s",model_dir,LOOP_MODEL_FILENAME);

    
    if(access(model_filename,F_OK) != 0)
    {
        state_filename = dump_state(0,LOOP_STATE_PREFIX,dump_dir);
        sprintf(cmd,"python3  ../../script/dataflow_modelling/infinite_loop.py -s %s -o %s -c %s > /dev/null 2>&1",state_filename,model_filename,fuzzware_config_filename);
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


void model_dumped_irq(int irq,hw_addr isr)
{
    char *state_filename;
    char model_filename[PATH_MAX];
    char cmd[PATH_MAX];
    char line[PATH_MAX];
    char *addr_size_ptr;

    FILE *f;

    
    sprintf(model_filename,"%s/%s",model_dir,IRQ_MODEL_FILENAME);

    // if(access(model_filename,F_OK) != 0)
    // {

        state_filename = dump_state(irq,IRQ_STATE_PREFIX,dump_dir);

        sprintf(cmd,"pc: %x  irq_entry: %x   ",(uint32_t)get_arm_pc(),isr);
        printf("%s",cmd);
        fprintf(f_irq_log,"%s",cmd);

        sprintf(cmd,"python3 ../../script/dataflow_modelling/irq_model.py -s %s -v 0x%x -i %d -o %s -c %s > /dev/null 2>&1",state_filename,get_nvic_vecbase(), irq,model_filename,fuzzware_config_filename);
        puts(cmd);

        fprintf(f_irq_log,"%s\n",cmd);
        system(cmd);
        free(state_filename);
        
    // }
        

        
    f = fopen(model_filename,"r");
    if(!f)
    {
        printf("model file %s not found,exit\n",model_filename);
        terminate_simulation();
    }

    
    bool start = false;
    int type;

    bool to_end;

    while(fgets(line, PATH_MAX, f))
    {
        if(strstr(line,"-"))
        {
            int tmp_irq = strtol(strstr(line,"-") + 1,0,10);
            if(tmp_irq == irq)
                start = true;
            else
                start = false;
            if(strstr(line,"y"))
                to_end = true;
            else
                to_end = false;

                
            continue;
        }
        if(!start)
            continue;
        if(!to_end)
        {
            printf("this IRQ has infinite loop\n");
            break;
        }
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
        if(!addr)
            continue;
        if(type == STOPWATCH_TYPE_MEM)
        {
            add_memory_access_watchpoint(irq,  addr,isr);
            
        }
        else if(type == STOPWATCH_TYPE_MMIO)
        {
                       
        }
        else if(type == STOPWATCH_TYPE_FUNC_POINTER)
        {
            add_unsolved_func_ptr(irq,addr,isr);
            
        }
        else if(type == STOPWATCH_TYPE_DEPENDENCY)
        {
            add_dependency_func_ptr(irq,addr,isr);
        }
        
    }
    puts("model done");

        
    fclose(f);
}