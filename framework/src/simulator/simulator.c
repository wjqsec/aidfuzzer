#include <stdbool.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h> 
#include <sys/types.h>
#include <sys/shm.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <glib.h>
#include <string.h>
#include <kk_ihex_write.h>
#include "xx.h"
#include "config.h"
#include "fuzzer.h"



//#define DBG
#define CRASH_DBG


struct SIMULATOR_CONFIG* global_config;
#include "snapshot.h"


uint8_t *__afl_share_fuzz_queue_data;
uint8_t *__afl_share_stream_data;
uint8_t *__afl_undiscover_stream_data;
uint8_t *__afl_discovered_irq_data;


uint8_t *__afl_area_ptr;
uint32_t __afl_prev_loc;


int fd_to_fuzzer, fd_from_fuzzer;

FILE *flog;
FILE *f_crash_log;


uint32_t max_bbl_exec = 1000000;


bool should_exit = false;
uint32_t exit_code;
uint32_t exit_info;
uint64_t exit_pc;
uint32_t num_mmio;



GArray* dumped_state_ids;

bool dumped_irq[NVIC_MAX_VECTORS];

int mem_trigger_irq_times[NVIC_MAX_VECTORS];  // insert an irq when the corresponding memory is accessed for n times.

uint32_t run_index;

char *dump_dir;
char *model_dir;
char *log_dir;



struct SHARED_STREAMS
{
    uint32_t stream_id;
    int32_t len;
    int32_t *used;
    uint32_t type;
    int32_t element_size;
    int32_t left_shift;
    uint8_t *data;
};

GArray* fuzz_streams;
int32_t* num_new_streams;
uint32_t* new_streams;



void collect_streams()
{

    struct SHARED_STREAMS *stream;
    int i = 0;
    uint32_t *current_queue_offset = (uint32_t *)__afl_share_fuzz_queue_data;
    uint32_t offset;
    uint8_t *ptr;
    while((offset = current_queue_offset[i]) != 0xffffffff)
    {
        ptr = __afl_share_stream_data + offset;
        stream = g_array_index(fuzz_streams, struct SHARED_STREAMS*, i / 2);
        stream->stream_id = *(uint32_t*)ptr;
        stream->len = *(int32_t*)(ptr + sizeof(stream->stream_id));
        stream->type = *(uint32_t*)(ptr + sizeof(stream->stream_id) + sizeof(stream->len));
        stream->element_size = *(int32_t*)(ptr + sizeof(stream->stream_id) + sizeof(stream->len) + sizeof(stream->type));
        stream->left_shift = *(int32_t*)(ptr + sizeof(stream->stream_id) + sizeof(stream->len) + sizeof(stream->type) + sizeof(stream->element_size));
        //stream->used = (int32_t*)(ptr + sizeof(stream->stream_id) + sizeof(stream->len) + sizeof(stream->type) + sizeof(stream->element_size) + sizeof(stream->left_shift));
        stream->used = &current_queue_offset[i+1];
        stream->data = (uint8_t*)(ptr + sizeof(stream->stream_id) + sizeof(stream->len) + sizeof(stream->type) + sizeof(stream->element_size) + sizeof(stream->left_shift) + sizeof(*stream->used));
        *stream->used = 0;
        i += 2;
    }

    stream = g_array_index(fuzz_streams, struct SHARED_STREAMS*, i / 2);

    stream->stream_id = 0;
}
inline bool discovered_stream(uint32_t stream_id)
{
    for(int i = 0; i < *num_new_streams; i++)
    {
        if(new_streams[i] == stream_id)
            return true;
    }
    return false;
}
inline struct SHARED_STREAMS* find_stream(uint32_t stream_id)
{
    struct SHARED_STREAMS *ret = NULL, *tmp;
    for (int i = 0; ; i++) 
    {
        
        tmp = g_array_index(fuzz_streams, struct SHARED_STREAMS*, i);
        if(tmp->stream_id == 0)
            break;
        
        if(tmp->stream_id == stream_id)
        {
            ret = tmp;
            break;
        }
    }
    return ret;
}

void __afl_map_shm(void) {

    char *id_str = getenv(SHM_ENV_VAR);
    if (id_str) {
    uint32_t shm_id = atoi(id_str);
    __afl_area_ptr = shmat(shm_id, NULL, 0);
    if (__afl_area_ptr == (void *)-1) _exit(1);
    }

    id_str = getenv(SHM_SHARE_STREAM_VAR);
    if (id_str) {
    uint32_t shm_id = atoi(id_str);
    __afl_share_stream_data = shmat(shm_id, NULL, 0);
    if (__afl_share_stream_data == (void *)-1) _exit(1);
    }

    id_str = getenv(SHM_SHARE_UNDISCOVER_STREAM_VAR);
    if (id_str) {
    uint32_t shm_id = atoi(id_str);
    __afl_undiscover_stream_data = shmat(shm_id, NULL, 0);
    if (__afl_undiscover_stream_data == (void *)-1) _exit(1);
    }

    id_str = getenv(SHM_SHARE_FUZZ_QUEUE_VAR);
    if (id_str) {
    uint32_t shm_id = atoi(id_str);
    __afl_share_fuzz_queue_data = shmat(shm_id, NULL, 0);
    if (__afl_share_fuzz_queue_data == (void *)-1) _exit(1);
    }

    num_new_streams = (uint32_t*)__afl_undiscover_stream_data;
    new_streams = num_new_streams + 1;

}




void start_new()
{
    uint32_t tmp;
    read(fd_from_fuzzer,&tmp,4);  // start new run
}

void exit_with_code_start_new()
{
    
    #ifdef DBG
    fprintf(flog,"%d->exit_code = %x pc = %x\n",run_index, exit_code,exit_pc);
    run_index++;
    #endif


    

    static uint32_t buf[128];
    buf[0] = exit_code;
    buf[1] = exit_info;
    buf[2] = exit_pc;
    buf[3] = num_mmio;

    write(fd_to_fuzzer , buf,EXIT_INFORMATION_SIZE);   
    arm_restore_snapshot(new_snap);
    num_mmio = 0;
    // __afl_prev_loc = 0;

    should_exit = false;
    memset(mem_trigger_irq_times, 0, NVIC_MAX_VECTORS * sizeof(int));

    start_new();
    *num_new_streams = 0;
    collect_streams();
    
    
}
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
        use_precise_pc ? (uint32_t)get_arm_precise_pc() : state.regs[15],
        state.regs[13],
        state.xpsr
    );
    ihex_init(&ihex);
    for(i = 0; i < NUM_MEM_SNAPSHOT ; i++)
    {
        if(global_config->rams[i].size == 0)
            break;
        buf = (uint8_t *)malloc(global_config->rams[i].size);
        read_ram(global_config->rams[i].start,global_config->rams[i].size,buf);
        ihex_write_at_address(&ihex, global_config->rams[i].start);
        ihex_write_bytes(&ihex, buf, global_config->rams[i].size);

        free(buf);
    }
    for(i = 0; i < NUM_MEM_SNAPSHOT ; i++)
    {
        if(global_config->roms[i].size == 0)
            break;
        buf = (uint8_t *)malloc(global_config->roms[i].size);
        read_ram(global_config->roms[i].start,global_config->roms[i].size,buf);
        ihex_write_at_address(&ihex, global_config->roms[i].start);
        ihex_write_bytes(&ihex, buf, global_config->roms[i].size);

        free(buf);
    }
    ihex_end_write(&ihex);

    fclose(state_file);

}
void prepare_exit(uint32_t code,uint32_t info,uint64_t pc)
{
    should_exit = true;
    exit_code = code;
    exit_info = info;
    exit_pc = pc;
}
void get_fuzz_data(struct SHARED_STREAMS * stream, uint64_t *out,uint64_t precise_pc)
{
    switch(stream->type)
    {
        case MODEL_VALUE_SET:
        {

            uint32_t num_values = *(uint32_t *)(stream->data);

            uint32_t *value_set = (uint32_t *)(stream->data + sizeof(uint32_t));

            // uint8_t *fuzz_data = stream->data  + sizeof(uint32_t) + num_values * sizeof(uint32_t);

            if(unlikely(*stream->used == 0))
                *stream->used = sizeof(uint32_t) + num_values * sizeof(uint32_t);
            
            if(stream->len - *stream->used < stream->element_size)
            {

                *out = value_set[0];  //give it a default one
                prepare_exit(EXIT_OUTOFSEED,stream->stream_id,precise_pc);

            }
                
            else
            {
                uint32_t tmp = 0;
                memcpy(&tmp,stream->data + *stream->used,stream->element_size);
                *out = value_set[tmp % num_values];
                *stream->used += stream->element_size;

            }    
        }
        break;
        
        case MODEL_CONSTANT:
        {
            *out = *(uint32_t*)(stream->data);
        }
        break;
        case MODEL_BIT_EXTRACT:
        {
            if(stream->len - *stream->used < stream->element_size)
            {
                prepare_exit(EXIT_OUTOFSEED,stream->stream_id,precise_pc);
            }
            else
            {
                memcpy(out,stream->data + *stream->used,stream->element_size);
                *out = *out << stream->left_shift;
                *stream->used += stream->element_size;
            }
        }
        break;
        case MODEL_PASSTHROUGH:
        {
            
        }
        break;

        case MODEL_NONE:
        {
            if(stream->len - *stream->used < stream->element_size)
            {
                prepare_exit(EXIT_OUTOFSEED,stream->stream_id,precise_pc);
            }
                
            else
            {
                
                memcpy(out,stream->data + *stream->used,stream->element_size);
                *stream->used += stream->element_size;
            }    
        }
        break;
        default:
        {
            printf("wrong stream type:%d\n",stream->type);
            exit(0);
        }
        break;
    } 
}

uint64_t mmio_read_common(void *opaque,hwaddr addr,unsigned size)
{
    int i;
    addr = (hwaddr)opaque + addr;
    uint64_t precise_pc = get_arm_precise_pc();
    uint64_t ret = 0;
    bool already_dumped_mmio_state = false;


    if(should_exit)
        return ret;

    uint32_t stream_id = hash_32_ext(addr) ^ hash_32_ext(precise_pc) ;//& 0xfffffff0;
    

    struct SHARED_STREAMS * stream =  find_stream(stream_id);

    if(!stream)
    {
        //if(!discovered_stream(stream_id))
        {
            new_streams[*num_new_streams] = stream_id;
            (*num_new_streams)++;

            
            for(i = 0 ;i < dumped_state_ids->len ; i++)
            {
                if(g_array_index(dumped_state_ids, uint32_t, i) == stream_id)
                    already_dumped_mmio_state = true;
            }
            
            if(!already_dumped_mmio_state)
            {
                g_array_append_val(dumped_state_ids, stream_id);
                dump_state(stream_id,true,MMIO_STATE_PREFIX,dump_dir);
            }
                
            prepare_exit(EXIT_NONE,stream_id,precise_pc);
        }

    }
    else
    {
        num_mmio++;
        get_fuzz_data(stream, &ret,precise_pc);     
    }


    #ifdef DBG
    struct ARM_CPU_STATE state;
    get_arm_cpu_state(&state);
    fprintf(flog,"%d->mmio read pc:%p mmio_addr:%x val:%x stream_id:%x\n",run_index, get_arm_precise_pc(),addr,ret,stream_id);
    #endif
    return ret;
}

void mmio_write_common(void *opaque,hwaddr addr,uint64_t data,unsigned size)
{
    
    #ifdef DBG
    
    addr = (hwaddr)opaque + addr;
    uint64_t precise_pc = get_arm_precise_pc();
    uint32_t stream_id = hash_32_ext(addr) ^ hash_32_ext(precise_pc) ;
    struct ARM_CPU_STATE state;
    get_arm_cpu_state(&state);
    fprintf(flog,"%d->mmio write pc:%p mmio_addr:%x val:%x stream_id:%x\n",run_index, get_arm_precise_pc(),addr,data,stream_id);
    #endif
}


bool arm_exec_bbl(hwaddr pc,uint32_t id,int64_t bbl)
{

    if(unlikely(bbl >= max_bbl_exec))
    {

        prepare_exit(EXIT_TIMEOUT,0,pc);
        exit_with_code_start_new();

        return true;
    }
    if(unlikely(should_exit))  //run out of seed
    {

        exit_with_code_start_new();

        return true;
    }
    
    #ifdef ENABLE_IRQ
    if(bbl != 0 && *num_irqs && (bbl & 0xff) == 0)
    {
        struct SHARED_STREAMS* stream =  find_stream(IRQ_STREAM_ID);
        if(!stream)
        {
            printf("fatal:not irq stream found\n");
            exit(0);
        }
        else
        {
            uint64_t tmp;
            get_fuzz_data(stream, &tmp,pc);     
            insert_nvic_intc(irqs[tmp % (*num_irqs)],false);
            #ifdef DBG
            fprintf(flog,"insert irq %d\n",irqs[tmp % (*num_irqs)]);
            #endif
        }
    }
    #endif




    #ifdef DBG
    fprintf(flog,"%d->bbl pc:%p\n",run_index, pc);
    #endif
    


    // __afl_area_ptr[id ^ __afl_prev_loc] ++;
    // __afl_prev_loc = id >> 1;
    __afl_area_ptr[id] ++;
    





    return false;
    

    
}
void nostop_watchpoint_exec(hwaddr vaddr,hwaddr len,hwaddr hitaddr,void *data)
{
    bool insert_irq;
    int irq = (int)(uint64_t)data;
    if(!get_arm_v7m_is_handler_mode() && mem_trigger_irq_times[irq] > 10)
    {

        insert_irq = insert_nvic_intc(irq);
        mem_trigger_irq_times[irq] = 0;
        #ifdef DBG
        if(insert_irq)
            fprintf(flog,"%d->insert irq:%d pc:%x stopwatch hit addr:%x\n",run_index,irq,get_arm_precise_pc(),hitaddr);
        #endif
       
    }
    mem_trigger_irq_times[irq] ++;
}

bool arm_cpu_do_interrupt_hook(int32_t exec_index)
{  
    
    struct ARM_CPU_STATE state;
    #ifdef DBG
    get_arm_cpu_state(&state);
    fprintf(flog,"%d->arm_cpu_do_interrupt index:%d pc:%x\n",run_index, exec_index,state.regs[15]);
    #endif

    
    if(exec_index == EXCP_SWI || exec_index == EXCP_IRQ || exec_index == EXCP_EXCEPTION_EXIT)
    {
        return true;
    }
    
    #ifdef CRASH_DBG
    get_arm_cpu_state(&state);
    uint32_t sp0, sp1,sp2;
    read_ram(state.regs[13],4, &sp0);
    read_ram(state.regs[13] + 4,4, &sp1);
    read_ram(state.regs[13] + 8,4, &sp2);
    fprintf(f_crash_log,"crash index:%d pc:%p  r0:%x, r1:%x, r2:%x, r3:%x, r4:%x r5:%x r6:%x r7:%x r8:%x r9:%x r10:%x r11:%x ip:%x sp:%x lr:%x sp:%x [sp]=%x, [sp+4]=%x [sp+8]=%x\n",
    exec_index,state.regs[15], state.regs[0],state.regs[1],state.regs[2],state.regs[3],state.regs[4],state.regs[5],state.regs[6],state.regs[7],state.regs[8],state.regs[9],
    state.regs[10],state.regs[11],state.regs[12],state.regs[13],state.regs[14], sp0, sp1,sp2);
    #endif

    prepare_exit(EXIT_CRASH,0,state.regs[15]);
    exit_with_code_start_new();
    return false;
}


void enable_nvic_hook(int irq)
{
    
    char state_filename[PATH_MAX];
    char model_filename[PATH_MAX];
    char cmd[PATH_MAX];
    char line[PATH_MAX];
    char *addr_size_ptr;
    struct ARM_CPU_STATE state;
    FILE *f;
    
    
    #ifdef DBG
    fprintf(flog,"%d->enable irq:%d pc:%x\n",run_index, irq,get_arm_precise_pc());
    #endif

    #ifndef ENABLE_IRQ
    if(!dumped_irq[irq] && irq >= 15)
    {
        sprintf(state_filename,"%s/%s%08x",dump_dir,IRQ_STATE_PREFIX,irq);
        sprintf(model_filename,"%s/%s",model_dir,IRQ_MODEL_FILENAME);
        dump_state(irq,false,IRQ_STATE_PREFIX,dump_dir);
        printf("pc:%x  ",get_arm_precise_pc());
        sprintf(cmd,"python3 /home/w/hd/iofuzzer/xxfuzzer/dataflow_modelling/irq_model.py %s %s %x > /dev/null 2>&1",state_filename,model_filename,irq);
        puts(cmd);
        system(cmd);
        
        f = fopen(model_filename,"r");
        
        bool start = false;
        int type;
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
            if(strstr(line,"mmio:"))
            {
                type = STOPWATCH_TYPE_MMIO;
                addr_size_ptr = line + strlen("mmio:");
                continue;
            }
                
            uint32_t addr = strtol(addr_size_ptr, 0, 16);
            uint32_t len = strtol(strstr(addr_size_ptr," ") + 1, 0, 16);
            if(!addr)
                continue;
            insert_nostop_watchpoint(addr,len,BP_MEM_ACCESS | BP_CALLBACK_ONLY_NO_STOP,nostop_watchpoint_exec,(void*)(uint64_t)irq);
            printf("insert_nostop_watchpoint irq:%d addr:%x\n",irq,addr);
        }
        fclose(f);
        puts("model done");
        dumped_irq[irq] = true;
    }

    #endif
    
}
void post_thread_exec(int exec_ret)
{

    #ifdef DBG
    struct ARM_CPU_STATE state;

    get_arm_cpu_state(&state);
    fprintf(flog,"%d->post thread exec:%d  pc:%p\n",run_index, exec_ret,state.regs[15]);
    #endif
}
void exec_ins_icmp(hwaddr pc,uint64_t val1,uint64_t val2, int used_bits, int immediate_index)
{
    #ifdef DBG
    fprintf(flog,"%d->ins icmp pc:%p\n",run_index, pc);
    #endif
}
//////////////////////////////////////////////////snapshot below

hwaddr snapshot_point = 0;
uint64_t mmio_read_snapshot(void *opaque,hwaddr addr,unsigned size)
{
    static bool found = false;
    if(!found)
    {
        struct ARM_CPU_STATE state;
        get_arm_cpu_state(&state);
        snapshot_point = state.regs[15];
        found = true;
    }
    return 0;
    
}
void mmio_write_snapshot(void *opaque,hwaddr addr,uint64_t data,unsigned size){}

bool exec_bbl_snapshot(hwaddr pc,uint32_t id,int64_t bbl)
{
    int i;
    static bool returned = false;
    if(snapshot_point == pc)
    {
        register_arm_do_interrupt_hook(arm_cpu_do_interrupt_hook);
        register_post_thread_exec_hook(post_thread_exec);
        register_exec_bbl_hook(arm_exec_bbl);
        register_enable_nvic_hook(enable_nvic_hook);
        for(i = 0; i < 255 ; i++)
        {
            if(global_config->mmios[i].size == 0)
                break;
            add_mmio_region(global_config->mmios[i].name,global_config->mmios[i].start, global_config->mmios[i].size, mmio_read_common, mmio_write_common,(void*)global_config->mmios[i].start);
        }
        new_snap = arm_take_snapshot();
        arm_restore_snapshot(new_snap);
        

        uint32_t tmp; 
        write(fd_to_fuzzer , &tmp,4);  //forkserver up
        //num_irqs = get_enabled_nvic_irq2(&irqs);
        start_new();
        collect_streams();

        return true;
    }
    else if(snapshot_point && !returned)
    {
        arm_restore_snapshot(org_snap);
        returned = true;
        return true;
    }
    __afl_area_ptr[id] ++;
    return false;
}


void init(int argc, char **argv)
{
    int opt;
    while ((opt = getopt(argc, argv, "d:m:l:f:t:")) != -1) 
    {
        switch (opt) {
        case 'd':
            dump_dir = optarg;
            break;
        case 'm':
            model_dir = optarg;
            break;
        case 'l':
            log_dir = optarg;
            break;
        case 'f':
            fd_from_fuzzer = atoi(optarg);
            break;
        case 't':
            fd_to_fuzzer = atoi(optarg);
            break;
        default: /* '?' */
            printf("Usage error\n");
            exit(0);
        }
    }

    char path_buffer[PATH_MAX];
    sprintf(path_buffer,"%s/simulator_log.txt",log_dir);
    flog = fopen(path_buffer,"w");
    sprintf(path_buffer,"%s/simulator_crash.txt",log_dir);
    f_crash_log = fopen(path_buffer,"w");

    setbuf(flog,0);
    setbuf(f_crash_log,0);


    struct SHARED_STREAMS* stream;
    fuzz_streams = g_array_new(FALSE, FALSE, sizeof(struct SHARED_STREAMS*));
    for(int i = 0; i < 200 ;i ++)
    {
        stream = (struct SHARED_STREAMS *)malloc(sizeof(struct SHARED_STREAMS));
        g_array_append_val(fuzz_streams, stream); 
    }
    __afl_map_shm();
    dumped_state_ids = g_array_new(FALSE, FALSE, sizeof(uint32_t));

    memset(dumped_irq, 0, NVIC_MAX_VECTORS);
    memset(mem_trigger_irq_times, 0, NVIC_MAX_VECTORS * sizeof(int));
    

}

int run_config(struct SIMULATOR_CONFIG *config)
{
    int i = 0;
    global_config = config;

    struct Simulator *simulator;
    simulator = create_simulator(ARM_CORTEX_M,false);
    if(config->vecbase)
        set_armv7_vecbase(config->vecbase);
    init_simulator(simulator);

    for(i = 0; i < MAX_NUM_MEM_REGION ; i++)
    {
        if(config->rams[i].size == 0)
            break;
        add_ram_region(config->rams[i].name,config->rams[i].start, config->rams[i].size,config->rams[i].readonly);
        if(config->rams[i].file)
        {
            load_file_ram(config->rams[i].file,config->rams[i].start,config->rams[i].file_offset,config->rams[i].file_size);
        }
        else
        {
            uint8_t *buf = (uint8_t *)malloc(config->rams[i].size);
            memset(buf,0,config->rams[i].size);
            write_ram(config->rams[i].start,config->rams[i].size,buf);
            free(buf);
        }
    }
    for(i = 0; i < MAX_NUM_MEM_REGION ; i++)
    {
        if(config->roms[i].size == 0)
            break;
        add_rom_region(config->roms[i].name,config->roms[i].start, config->roms[i].size);
        if(config->roms[i].file)
        {
            load_file_rom(config->roms[i].file,config->roms[i].start,config->roms[i].file_offset,config->roms[i].file_size);
        }
            
    }
    
    for(i = 0; i < MAX_NUM_MEM_REGION ; i++)
    {
        if(config->mmios[i].size == 0)
            break;
        add_mmio_region(config->mmios[i].name,config->mmios[i].start, config->mmios[i].size, mmio_read_snapshot, mmio_write_snapshot,(void*)config->mmios[i].start);
    }
    reset_arm_reg();
    
    register_exec_bbl_hook(exec_bbl_snapshot);
    org_snap = arm_take_snapshot();
    exec_simulator(simulator);
}
