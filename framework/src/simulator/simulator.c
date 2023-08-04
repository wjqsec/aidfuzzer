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
#include <sys/time.h>
#include "xx.h"
#include "config.h"
#include "fuzzer.h"



//#define DBG
#define CRASH_DBG
//#define MMIO_READ_DBG
#define EXIT_DBG


char *fuzzware_config_filename;
struct SIMULATOR_CONFIG* config;
#include "snapshot.h"


uint8_t *__afl_share_fuzz_queue_data;
uint8_t *__afl_share_stream_data;
uint8_t *__afl_undiscover_stream_data;
uint8_t *__afl_area_ptr;
uint32_t __afl_prev_loc;


int fd_to_fuzzer, fd_from_fuzzer;

FILE *flog;
FILE *f_crash_log;


uint64_t nommio_executed_bbls;
uint64_t max_bbl_exec = MAX_BBL_EXEC;


bool should_exit = false;
struct EXIT_INFO exit_info;
uint32_t num_mmio;



bool dumped_irq[NVIC_MAX_VECTORS];

uint8_t mem_trigger_irq_times[NVIC_MAX_VECTORS];  // insert an irq when the corresponding memory is accessed for n times.

uint32_t run_index;

char *dump_dir;
char *model_dir;
char *log_dir;



struct SHARED_STREAM
{
    struct stream_metadata *metadata;
    u32 used;
    bool avaliable;
    bool dumped;
};
struct undiscovered_streams *undiscover_streams;
struct SHARED_STREAM * streams[NUM_QUEUE_STREAMS];




void collect_streams()
{
    u32 i,index;
    struct SHARED_STREAM *stream;
    struct stream_metadata *metadata;
    for(i = 0 ; i < NUM_QUEUE_STREAMS ; i++)
    {
        streams[i]->avaliable = false;
    }
    struct fuzz_queue *queue = (struct fuzz_queue *)__afl_share_fuzz_queue_data;
    for(i = 0; i < queue->num_streams ; i++)
    {
        metadata = (struct stream_metadata *)(__afl_share_stream_data + queue->streams[i].offset_to_stream_area);
        index = metadata->stream_id % NUM_QUEUE_STREAMS;
        if(streams[index]->avaliable)
        {
            printf("stream index colission\n");
            exit(0);
        }
        streams[index]->avaliable = true;
        streams[index]->used = 0;
        streams[index]->metadata = metadata;
        
    }
    
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

    undiscover_streams = (struct undiscovered_streams *)__afl_undiscover_stream_data;

}


void terminate()
{

    shmdt(__afl_area_ptr);
    shmdt(__afl_share_stream_data);
    shmdt(__afl_undiscover_stream_data);
    shmdt(__afl_share_fuzz_queue_data);
    exit_info.exit_code = EXIT_TERMINATE;
    write(fd_to_fuzzer , &exit_info,sizeof(struct EXIT_INFO));  //forkserver up
    while (1)
    {
        ;
    }
    
}

void start_new()
{
    uint32_t tmp;
    read(fd_from_fuzzer,&tmp,4);  // start new run
    if(unlikely(tmp == CMD_TERMINATE))
        terminate();
}

void exit_with_code_start_new()
{
    
    
    #ifdef DBG
    fprintf(flog,"%d->exit_code = %x pc = %x\n",run_index, exit_info.exit_code,exit_info.exit_pc);
    
    #endif
    
    write(fd_to_fuzzer , &exit_info,sizeof(struct EXIT_INFO));   
    start_new();

    undiscover_streams->num_streams = 0;
    collect_streams();
    num_mmio = 0;
    arm_restore_snapshot(new_snap);
    nommio_executed_bbls = 0;
    run_index++;
    should_exit = false;
    memset(mem_trigger_irq_times, 0, NVIC_MAX_VECTORS * sizeof(mem_trigger_irq_times[0]));
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
        if(config->rams[i].size == 0)
            break;
        buf = (uint8_t *)malloc(config->rams[i].size);
        read_ram(config->rams[i].start,config->rams[i].size,buf);
        ihex_write_at_address(&ihex, config->rams[i].start);
        ihex_write_bytes(&ihex, buf, config->rams[i].size);

        free(buf);
    }
    for(i = 0; i < NUM_MEM_SNAPSHOT ; i++)
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
void prepare_exit(uint32_t code,uint32_t oufofseed_mmio_id,uint64_t pc,uint32_t num_mmio)
{
    should_exit = true;
    exit_info.exit_code = code;
    exit_info.exit_oufofseed_mmio_id = oufofseed_mmio_id;
    exit_info.exit_pc = pc;
    exit_info.num_mmio = num_mmio;
}

bool get_fuzz_data(struct SHARED_STREAM * stream, uint64_t *out)
{

    switch(stream->metadata->mode)
    {
        case MODEL_VALUE_SET:
        {
            nommio_executed_bbls = 0;
            if(stream->metadata->len - stream->used < stream->metadata->element_size)
            {

                *out = stream->metadata->value_set[0];  //give it a default one
                return false;

            }
            else
            {
                uint32_t tmp = 0;
                memcpy(&tmp,stream->metadata->data + stream->used,stream->metadata->element_size);
                *out = stream->metadata->value_set[tmp % stream->metadata->value_set_size];
                stream->used += stream->metadata->element_size;
                return true;
            }    
        }
        break;
        
        case MODEL_CONSTANT:
        {
            *out = *(uint32_t*)(stream->metadata->data);
        }
        break;
        case MODEL_BIT_EXTRACT:
        {
            nommio_executed_bbls = 0;
            if(stream->metadata->len - stream->used < stream->metadata->element_size)
            {
                return false;
            }
            else
            {
                memcpy(out,stream->metadata->data + stream->used,stream->metadata->element_size);
                *out = *out << stream->metadata->left_shift;
                stream->used += stream->metadata->element_size;
                return true;
            }
        }
        break;
        case MODEL_PASSTHROUGH:
        {
            return true;
        }
        break;

        case MODEL_NONE:
        {
            nommio_executed_bbls = 0;
            if(stream->metadata->len - stream->used < stream->metadata->element_size)
            {
                return false;
            }
                
            else
            {
                
                memcpy(out,stream->metadata->data + stream->used,stream->metadata->element_size);
                stream->used += stream->metadata->element_size;
                return true;
            }    
        }
        break;
        default:
        {
            printf("wrong stream type:%d\n",stream->metadata->mode);
            exit(0);
            return false;
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
    bool outofseed;
    

    if(should_exit)
        return ret;

    uint32_t stream_id = hash_32_ext(addr) ^ hash_32_ext(precise_pc) ;
    
    uint32_t index = stream_id % NUM_QUEUE_STREAMS;
    struct SHARED_STREAM * stream =  streams[index];


    if(!stream->avaliable)
    {
        undiscover_streams->streams[undiscover_streams->num_streams++] = stream_id;

        
        if(!stream->dumped)
        {
            dump_state(stream_id,true,MMIO_STATE_PREFIX,dump_dir);
            stream->dumped = true;
        }
            
        prepare_exit(EXIT_NONE,stream_id,precise_pc,num_mmio);


    }
    else
    {
        num_mmio++;
        outofseed = get_fuzz_data(stream, &ret);     
        if(!outofseed)
            prepare_exit(EXIT_OUTOFSEED,stream_id,precise_pc,num_mmio);

    }


    #ifdef DBG
    struct ARM_CPU_STATE state;
    get_arm_cpu_state(&state);
    fprintf(flog,"%d->mmio read pc:%p mmio_addr:%x val:%x stream_id:%x\n",run_index, get_arm_precise_pc(),addr,ret,stream_id);
    #endif

    #ifdef MMIO_READ_DBG
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
    if(unlikely(nommio_executed_bbls >= max_bbl_exec))
    {

        prepare_exit(EXIT_TIMEOUT,0,pc,num_mmio);
        exit_with_code_start_new();

        return true;
    }
    if(unlikely(pc == 0x4500))
    {
        insert_nvic_intc(ARMV7M_EXCP_SYSTICK);
        insert_nvic_intc(0x28);
    }
    if(unlikely(should_exit))  //run out of seed
    {

        exit_with_code_start_new();

        return true;
    }
    
    #ifdef ENABLE_IRQ
    if(bbl != 0 && *num_irqs && (bbl & 0xff) == 0)
    {
        struct SHARED_STREAM* stream =  find_stream(IRQ_STREAM_ID);
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
    nommio_executed_bbls++;





    return false;
    

    
}
void nostop_watchpoint_exec(hwaddr vaddr,hwaddr len,hwaddr hitaddr,void *data)
{
    bool insert_irq;
    int irq = (int)(uint64_t)data;
    if(!get_arm_v7m_is_handler_mode())
    {
        if(mem_trigger_irq_times[irq] > 5)
        {
            insert_irq = insert_nvic_intc(irq);
            mem_trigger_irq_times[irq] = 0;
        }
        else
        {
             mem_trigger_irq_times[irq] ++;
        }
        
        #ifdef DBG
        if(insert_irq)
            fprintf(flog,"%d->insert irq:%d pc:%x stopwatch hit addr:%x\n",run_index,irq,get_arm_precise_pc(),hitaddr);
        #endif
       
    }
   
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
    
    #if defined(DBG) || defined(CRASH_DBG)
    get_arm_cpu_state(&state);
    uint32_t sp0, sp1,sp2;
    read_ram(state.regs[13],4, &sp0);
    read_ram(state.regs[13] + 4,4, &sp1);
    read_ram(state.regs[13] + 8,4, &sp2);
    #ifdef CRASH_DBG
    fprintf(f_crash_log,"%d->crash index:%d pc:%p  r0:%x, r1:%x, r2:%x, r3:%x, r4:%x r5:%x r6:%x r7:%x r8:%x r9:%x r10:%x r11:%x ip:%x sp:%x lr:%x sp:%x [sp]=%x, [sp+4]=%x [sp+8]=%x\n",
    run_index,exec_index,state.regs[15], state.regs[0],state.regs[1],state.regs[2],state.regs[3],state.regs[4],state.regs[5],state.regs[6],state.regs[7],state.regs[8],state.regs[9],
    state.regs[10],state.regs[11],state.regs[12],state.regs[13],state.regs[14], sp0, sp1,sp2);
    #endif
    #ifdef DBG
    fprintf(flog,"%d->crash index:%d pc:%p  r0:%x, r1:%x, r2:%x, r3:%x, r4:%x r5:%x r6:%x r7:%x r8:%x r9:%x r10:%x r11:%x ip:%x sp:%x lr:%x sp:%x [sp]=%x, [sp+4]=%x [sp+8]=%x\n",
    run_index,exec_index,state.regs[15], state.regs[0],state.regs[1],state.regs[2],state.regs[3],state.regs[4],state.regs[5],state.regs[6],state.regs[7],state.regs[8],state.regs[9],
    state.regs[10],state.regs[11],state.regs[12],state.regs[13],state.regs[14], sp0, sp1,sp2);
    #endif
    #endif

    prepare_exit(EXIT_CRASH,0,state.regs[15],num_mmio);
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
    if(!dumped_irq[irq] && irq > 15)
    {
        dumped_irq[irq] = true;
        return;
        sprintf(state_filename,"%s/%s%08x",dump_dir,IRQ_STATE_PREFIX,irq);
        sprintf(model_filename,"%s/%s",model_dir,IRQ_MODEL_FILENAME);
        dump_state(irq,false,IRQ_STATE_PREFIX,dump_dir);
        printf("pc:%x  ",get_arm_precise_pc());
        sprintf(cmd,"python3 /home/w/hd/iofuzzer/xxfuzzer/dataflow_modelling/irq_model.py -s %s -i %x -o %s -c %s > /dev/null 2>&1",state_filename,irq,model_filename,fuzzware_config_filename);
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
        
    }

    #endif
    
}
void post_thread_exec(int exec_ret)
{
    struct ARM_CPU_STATE state;
    #ifdef DBG

    get_arm_cpu_state(&state);
    fprintf(flog,"%d->post thread exec:%d  pc:%p\n",run_index, exec_ret,state.regs[15]);
    #endif

    // #ifdef EXIT_DBG
    // get_arm_cpu_state(&state);
    // fprintf(flog,"%d->post thread exec:%d  pc:%p\n",run_index, exec_ret,state.regs[15]);
    // #endif

    get_arm_cpu_state(&state);
    prepare_exit(EXIT_TIMEOUT,0,state.regs[15],num_mmio);
    exit_with_code_start_new();

}

//////////////////////////////////////////////////snapshot below

hwaddr snapshot_point = 0;
struct ARM_CPU_STATE state111;
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
        for(i = 0; i < MAX_NUM_MEM_REGION ; i++)
        {
            if(config->mmios[i].size == 0)
                break;
            add_mmio_region(config->mmios[i].name,config->mmios[i].start, config->mmios[i].size, mmio_read_common, mmio_write_common,(void*)config->mmios[i].start);
        }
        new_snap = arm_take_snapshot();
        arm_restore_snapshot(new_snap);
        

        exit_info.exit_code = EXIT_FORKSRV_UP;
        write(fd_to_fuzzer , &exit_info,sizeof(struct EXIT_INFO));  //forkserver up
        
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
    #ifdef DBG
    fprintf(flog,"snapshot bbl:%x\n", pc);
    #endif
    __afl_area_ptr[id] ++;

    return false;
}




void init(int argc, char **argv)
{
    int opt;
    while ((opt = getopt(argc, argv, "c:d:m:l:f:t:")) != -1) 
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
        case 'c':
            fuzzware_config_filename = strdup(optarg);
            config = generate_xx_config(optarg);
            
            break;
        default: /* '?' */
            printf("Usage error\n");
            exit(0);
        }
    }
    if(!config)
        exit(0);
    char path_buffer[PATH_MAX];
    sprintf(path_buffer,"%s/simulator_log.txt",log_dir);
    flog = fopen(path_buffer,"w");
    sprintf(path_buffer,"%s/simulator_crash.txt",log_dir);
    f_crash_log = fopen(path_buffer,"w");

    setbuf(flog,0);
    setbuf(f_crash_log,0);


    for(int i = 0; i < NUM_QUEUE_STREAMS ;i ++)
    {
        streams[i] = (struct SHARED_STREAM *)malloc(sizeof(struct SHARED_STREAM));
        streams[i]->avaliable = false;
        streams[i]->dumped = false;
    }

    __afl_map_shm();

    memset(dumped_irq, 0, NVIC_MAX_VECTORS);
    memset(mem_trigger_irq_times, 0, NVIC_MAX_VECTORS * sizeof(mem_trigger_irq_times[0]));
    

}

int run_config()
{
    int i = 0;

    struct XXSimulator *simulator;
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
