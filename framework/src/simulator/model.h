#ifndef MODEL_INCLUDED
#define MODEL_INCLUDED

#define STOPWATCH_TYPE_MMIO 0
#define STOPWATCH_TYPE_MEM 1
#define STOPWATCH_TYPE_FUNC_POINTER 2


#define MAX_IRQ_MODEL_MEMORY_NUM 0x100
struct IRQ_MODEL
{
    uint32_t mem[MAX_IRQ_MODEL_MEMORY_NUM];
    uint32_t mmio[MAX_IRQ_MODEL_MEMORY_NUM];
    uint32_t func[MAX_IRQ_MODEL_MEMORY_NUM];
    uint32_t func_vals[MAX_IRQ_MODEL_MEMORY_NUM];
}irq_models[NVIC_MAX_VECTORS];

FILE *state_file;
void ihex_flush_buffer(struct ihex_state *ihex,char *buffer, char *eptr)
{
    *eptr = '\0';
    fputs(buffer,state_file);
}
void dump_state(uint32_t mmio_id, bool use_precise_pc, const char * prefix, char *dir)
{
    int i;
    uint8_t *buf;
    char state_filename[PATH_MAX];
    struct ARM_CPU_STATE state;
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
        use_precise_pc ? (uint32_t)get_arm_precise_pc() : (uint32_t)get_arm_pc(),
        state.regs[13],
        state.xpsr
    );
    ihex_init(&ihex);
    for(i = 0; i < MAX_NUM_MEM_REGION ; i++)
    {
        if(config->rams[i].size == 0)
            break;
        buf = (uint8_t *)malloc(config->rams[i].size);
        read_ram(config->rams[i].start,config->rams[i].size,buf);
        ihex_write_at_address(&ihex, config->rams[i].start);
        ihex_write_bytes(&ihex, buf, config->rams[i].size);

        free(buf);
    }
    for(i = 0; i < MAX_NUM_MEM_REGION ; i++)
    {
        if(config->roms[i].size == 0)
            break;
        buf = (uint8_t *)malloc(config->roms[i].size);
        read_ram(config->roms[i].start,config->roms[i].size,buf);
        ihex_write_at_address(&ihex, config->roms[i].start);
        ihex_write_bytes(&ihex, buf, config->roms[i].size);

        free(buf);
    }
    ihex_end_write(&ihex);

    fclose(state_file);

}
void model_all_infinite_loop()
{
    FILE *f;
    char state_filename[PATH_MAX];
    char model_filename[PATH_MAX];
    char line[PATH_MAX];
    char cmd[PATH_MAX];
    sprintf(state_filename,"%s/%s%08x",dump_dir,LOOP_STATE_PREFIX,0);
    sprintf(model_filename,"%s/%s",model_dir,LOOP_MODEL_FILENAME);

    
    if(access(model_filename,F_OK) != 0)
    {
        dump_state(0,false,LOOP_STATE_PREFIX,dump_dir);
        sprintf(cmd,"python3 ../../dataflow_modelling/irq_model.py -m %s -s %s -i %x -o %s -c %s > /dev/null 2>&1","loop",state_filename,0,model_filename,fuzzware_config_filename);
        puts(cmd);
        system(cmd);
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
        printf("model file %s\n not found,exit\n",model_filename);
        exit(0);
    }
}

inline bool find_value(uint32_t *data, int len, uint32_t val)
{
    for(int i = 0; i < len; i ++)
    {
        if(data[i] == val)
            return true;
    }
    return false;
}

void model_irq(int irq)
{
    char state_filename[PATH_MAX];
    char model_filename[PATH_MAX];
    char cmd[PATH_MAX];
    char line[PATH_MAX];
    char *addr_size_ptr;
    struct ARM_CPU_STATE state;
    FILE *f;

    
    sprintf(state_filename,"%s/%s%08x",dump_dir,IRQ_STATE_PREFIX,irq);
    sprintf(model_filename,"%s/%s",model_dir,IRQ_MODEL_FILENAME);

    // if(access(model_filename,F_OK) != 0)
    // {

        dump_state(irq,false,IRQ_STATE_PREFIX,dump_dir);
        printf("pc:%x  ",(uint32_t)get_arm_pc());
        sprintf(cmd,"python3 ../../dataflow_modelling/irq_model.py -m %s -s %s -i 0x%x -o %s -c %s > /dev/null 2>&1","irq",state_filename,irq,model_filename,fuzzware_config_filename);
        puts(cmd);
        system(cmd);
        
    // }
        

        
    f = fopen(model_filename,"r");
    if(!f)
    {
        printf("model file %s\n not found,exit\n",model_filename);
        exit(0);
    }
    bool start = false;
    bool do_mmio_irq = false;
    int type;

    int mem_index = 0 ;
    int mmio_index = 0 ;
    int func_index = 0;

    while (irq_models[irq].mem[mem_index] != 0)
    {
        mem_index++;
    }
    while (irq_models[irq].mmio[mmio_index] != 0)
    {
        mmio_index++;
    }
    while (irq_models[irq].func[func_index] != 0)
    {
        func_index++;
    }
    

    while(fgets(line, PATH_MAX, f))
    {
        if(strstr(line,"-"))
        {
            int tmp_irq = strtol(strstr(line,"-") + 1,0,10);
            if(tmp_irq == irq)
                start = true;
            else
                start = false;
            continue;
        }
        if(!start)
            continue;
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

            
        uint32_t addr = strtol(addr_size_ptr, 0, 16);
        uint32_t len = strtol(strstr(addr_size_ptr," ") + 1, 0, 16);
        if(!addr)
            continue;
        if(type == STOPWATCH_TYPE_MEM)
        {
            if(find_value(irq_models[irq].mem,mem_index,addr))
                continue;
            insert_nostop_watchpoint(addr,len,QEMU_PLUGIN_MEM_R_ ,nostop_watchpoint_exec_mem,(void*)(uint64_t)irq);
            mem_access_trigger_irq_times[irq]++;
            do_mmio_irq = true;
            irq_models[irq].mem[mem_index++] = addr;
            printf("insert_nostop_watchpoint mem irq:%d addr:%x\n",irq,addr);
        }
        else if(type == STOPWATCH_TYPE_MMIO)
        {
            // if(find_value(irq_models[irq].mmio,mmio_index,addr))
            //     continue;
            

                
        }
        else if(type == STOPWATCH_TYPE_FUNC_POINTER)
        {
            if(find_value(irq_models[irq].func,func_index,addr))
                continue;
            insert_nostop_watchpoint(addr,len,QEMU_PLUGIN_MEM_W_ ,nostop_watchpoint_exec_func,(void*)(uint64_t)irq);
            irq_models[irq].func[func_index++] = addr;
            printf("insert_nostop_watchpoint func irq:%d addr:%x\n",irq,addr);
        }
        
    }
    puts("model done");
    if(do_mmio_irq)
        do_mmio_irqs[num_do_mmio_irqs++] = irq;
    fclose(f);
}
#endif