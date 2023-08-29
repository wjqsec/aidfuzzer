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
#include "simulator.h"

//#define DBG
#define CRASH_DBG



struct SIMULATOR_CONFIG* config;
#include "snapshot.h"


uint8_t *__afl_share_fuzz_queue_data;
uint8_t *__afl_share_stream_data;

uint16_t *__afl_area_ptr;
// uint32_t __afl_prev_loc;


int fd_to_fuzzer, fd_from_fuzzer;

FILE *flog;
FILE *f_crash_log;


uint64_t nommio_executed_bbls;
uint64_t max_bbl_exec = MAX_BBL_EXEC;


struct EXIT_INFO exit_info;
bool next_bbl_should_exit = false;
uint32_t num_mmio;



bool dumped_irq[NVIC_MAX_VECTORS];
uint8_t mem_access_trigger_irq_times_count[NVIC_MAX_VECTORS];  // insert an irq when the corresponding memory is accessed for n times.
uint8_t mem_access_trigger_irq_times[NVIC_MAX_VECTORS];
uint16_t do_mmio_irqs[NVIC_MAX_VECTORS];
int num_do_mmio_irqs;


uint32_t run_index;

char *dump_dir;
char *model_dir;
char *log_dir;
char *fuzzware_config_filename;

#include "model.h"
#include "log.h"


struct SHARED_STREAM
{
    struct stream_metadata *metadata;
    u32 *used;
    bool avaliable;
    bool dumped;
};
struct SHARED_STREAM * streams[NUM_QUEUE_STREAMS];

int num_stream_indexs;
u32 stream_indexs[NUM_QUEUE_STREAMS];

struct fuzz_queue *queue;



void prepare_exit(uint32_t code,uint32_t stream_id,uint64_t pc,uint32_t num_mmio,u32 stream_dumped);

void terminate()
{

    shmdt(__afl_area_ptr);
    shmdt(__afl_share_stream_data);
    shmdt(__afl_share_fuzz_queue_data);
    prepare_exit(EXIT_TERMINATE,0,0,0,0);
    write(fd_to_fuzzer , &exit_info,sizeof(struct EXIT_INFO));  //forkserver up
    while (1)
    {
        ;
    }
    
}
inline void add_stream(int index_to_shared_queue)
{
    
    u32 index_to_streams;
    struct SHARED_STREAM *stream;
    struct stream_metadata *metadata;
    
    metadata = (struct stream_metadata *)(__afl_share_stream_data + queue->streams[index_to_shared_queue].offset_to_stream_area);

    #ifdef STREAM_MAGIC_CHECK
    if(metadata->magic_number != STREAM_MAGIC)
    {
        printf("stream magic overwritten\n");
        exit(0);
    }
    #endif

    index_to_streams = metadata->stream_id % NUM_QUEUE_STREAMS;
    stream = streams[index_to_streams];
    if(stream->avaliable)
    {
        printf("stream index colission id:%x  %x\n",metadata->stream_id,stream->metadata->stream_id);
        exit(0);
    }
    stream->avaliable = true;
    stream->used = &queue->streams[index_to_shared_queue].used;
    stream->metadata = metadata;
    stream_indexs[num_stream_indexs] = index_to_streams;
    num_stream_indexs++;

}
inline void update_stream(int index_to_shared_queue)
{
    u32 index_to_streams;
    struct SHARED_STREAM *stream;
    struct stream_metadata *metadata;
    metadata = (struct stream_metadata *)(__afl_share_stream_data + queue->streams[index_to_shared_queue].offset_to_stream_area);
    index_to_streams = metadata->stream_id % NUM_QUEUE_STREAMS;
    stream = streams[index_to_streams];
    stream->metadata = metadata;
}
inline void clear_streams()
{
    u32 i;
    for(i = 0 ;i < num_stream_indexs; i++)
    {
        streams[stream_indexs[i]]->avaliable = false;
    }
    num_stream_indexs = 0;
}
void collect_streams()
{
    u32 i;

    clear_streams();
    for(i = 0; i < queue->num_streams ; i++)
    {
        add_stream(i);
    }   
}



bool exit_with_code_start()
{
    bool pc_changed;
    struct CMD_INFO cmd_info;

    

    write(fd_to_fuzzer , &exit_info,sizeof(struct EXIT_INFO));   

    read(fd_from_fuzzer,&cmd_info,sizeof(struct CMD_INFO)); 


    if(unlikely(cmd_info.cmd == CMD_TERMINATE))
    {
        terminate();
        pc_changed = true;
    }   
    else if(unlikely(cmd_info.cmd == CMD_CONTINUE_ADD_STREAM))
    {

        add_stream(cmd_info.added_stream_index);

        pc_changed = false;
    }
    else if(unlikely(cmd_info.cmd == CMD_CONTINUE_UPDATE_STREAM))
    {
        update_stream(cmd_info.updated_stream_index);
        pc_changed = false;
    }
    else if(unlikely(cmd_info.cmd == CMD_FUZZ))
    {
        pc_changed = true;
    }
    else
    {
        printf("invlaid cmd %d\n",cmd_info.cmd);
        exit(0);
        pc_changed = true;
    }
    if(pc_changed)
    {
        simple_log(flog,false,"exit",exit_info.exit_code,0,0);
        num_mmio = 0;
        nommio_executed_bbls = 0;
        run_index++;
        memset(mem_access_trigger_irq_times_count, 0, NVIC_MAX_VECTORS * sizeof(mem_access_trigger_irq_times_count[0]));
        arm_restore_snapshot(new_snap);
        collect_streams();
    }
    return pc_changed;
     
}

void prepare_exit(uint32_t code,uint32_t stream_id,uint64_t pc,uint32_t num_mmio,u32 stream_dumped)
{
    
    exit_info.exit_code = code;
    exit_info.exit_stream_id = stream_id;
    exit_info.stream_dumped = stream_dumped;
    exit_info.exit_pc = pc;
    exit_info.num_mmio = num_mmio;
}


inline int get_stream_status(struct SHARED_STREAM * stream)
{
    int status = STREAM_STATUS_OK;
    if( stream->metadata->len < stream->metadata->element_size + *stream->used)
    {
        if(stream->metadata->len > DEFAULT_MAX_STREAM_INCREASE_LEN)
        {
            status = STREAM_STATUS_OUTOF;
        }
        else
        {
            status = STREAM_STATUS_NOTENOUGH;
        }
    }
    return status;
}
void get_fuzz_data(struct SHARED_STREAM * stream, uint64_t *out)
{
    
    switch(stream->metadata->mode)
    {
        case MODEL_VALUE_SET:
        {

            uint32_t tmp = 0;
            memcpy(&tmp,stream->metadata->data + *stream->used,stream->metadata->element_size);
            *out = stream->metadata->value_set[tmp % stream->metadata->value_set_size];
            break;
        }
        case MODEL_CONSTANT:
        {
            *out = *(uint32_t*)(stream->metadata->data);
            break;
        }
        
        case MODEL_BIT_EXTRACT:
        {

            memcpy(out,stream->metadata->data + *stream->used,stream->metadata->element_size);
            *out = *out << stream->metadata->left_shift;
            break;
        }
        
        case MODEL_PASSTHROUGH:
        {
            break;
        }
       

        case MODEL_NONE:
        {

            memcpy(out,stream->metadata->data + *stream->used,stream->metadata->element_size);
            break;
        }
        
        default:
        {
            printf("wrong stream type:%d\n",stream->metadata->mode);
            exit(0);
            break;
        }
    } 

    num_mmio++;
    nommio_executed_bbls = 0;
    *stream->used += stream->metadata->element_size;

}

uint64_t mmio_read_common(void *opaque,hwaddr addr,unsigned size)
{
    uint64_t ret = 0;
    u32 stream_dumped = 1;
    if(next_bbl_should_exit)
        return ret;

    addr = (hwaddr)opaque + addr;
    uint64_t precise_pc = get_arm_precise_pc();
    
    int stream_status;
    bool pc_changed;

    uint32_t stream_id = hash_32_ext(addr) ^ hash_32_ext(precise_pc) ;
    uint32_t index = stream_id % NUM_QUEUE_STREAMS;
    struct SHARED_STREAM * stream =  streams[index];


    if(!stream->avaliable)
    {
        
        if(!stream->dumped)
        {
            stream_dumped = 0;
            dump_state(stream_id,true,MMIO_STATE_PREFIX,dump_dir);
            stream->dumped = true;
            
        }

        prepare_exit(EXIT_STREAM_NOTFOUND,stream_id,precise_pc,num_mmio,stream_dumped);
        exit_with_code_start();

        if(!stream->avaliable)
        {
            printf("stream not added by fuzzer id:%x\n",stream_id);
            exit(0);
        }
    }
    
    stream_status = get_stream_status(stream);
       
    if(likely(stream_status == STREAM_STATUS_OK))
    {
        get_fuzz_data(stream, &ret);  
    }
    else if(stream_status == STREAM_STATUS_NOTENOUGH)
    {
        do
        {
            prepare_exit(EXIT_NOTENOUGHT_STREAM,stream_id,precise_pc,num_mmio,stream_dumped);
            pc_changed = exit_with_code_start();
            stream_status = get_stream_status(stream);
            /* code */
        } while (stream_status != STREAM_STATUS_OK);
        get_fuzz_data(stream, &ret);  
       
    }
    else if(stream_status == STREAM_STATUS_OUTOF)
    {
        prepare_exit(EXIT_OUTOF_STREAM,stream_id,precise_pc,num_mmio,stream_dumped);
        next_bbl_should_exit = true;
    }
    else
    {

    }

    simple_log(flog,false,"mmio_read",addr,ret,stream_id);

    
    return ret;
}

void mmio_write_common(void *opaque,hwaddr addr,uint64_t data,unsigned size)
{
    
}


bool arm_exec_bbl(hwaddr pc,uint32_t id)
{
    bool pc_changed = false;
    if(unlikely(next_bbl_should_exit))
    {
        next_bbl_should_exit = false;
        pc_changed = exit_with_code_start();
        return pc_changed;
    }
    if(unlikely(nommio_executed_bbls >= max_bbl_exec))
    {

        prepare_exit(EXIT_TIMEOUT,0,pc,num_mmio,0);
        pc_changed = exit_with_code_start();
        return pc_changed;
    }
    
    #ifdef ENABLE_ROUNDROBIN_IRQ
    if(*num_irqs && (bbl % ROUNDROBIN_IRQ_BBLS) == 0)
    {
        insert_nvic_intc(irqs[tmp % (*num_irqs)],false);

    }
    #endif


    // __afl_area_ptr[id ^ __afl_prev_loc] ++;
    // __afl_prev_loc = id >> 1;
    
    __afl_area_ptr[id] ++;
    nommio_executed_bbls++;
    simple_log(flog,false,"bbl",0,0,0);
    
    return pc_changed;
}
bool arm_exec_loop_bbl(hwaddr pc,uint32_t id)
{
    bool insert_irq;
    insert_irq = insert_nvic_intc(ARMV7M_EXCP_SYSTICK);
    if(insert_irq)
        simple_log(flog,false,"arm_exec_loop_bbl",ARMV7M_EXCP_SYSTICK,0,0);
    
    for(int i=0; i<num_do_mmio_irqs ; i++)
    {
        insert_irq = insert_nvic_intc(do_mmio_irqs[i]);
        if(insert_irq)
            simple_log(flog,false,"arm_exec_loop_bbl",do_mmio_irqs[i],0,0);
    }
    return false;
}

void nostop_watchpoint_exec_mem(hwaddr vaddr,hwaddr len,uint32_t val, void *data)
{
    bool insert_irq;
    int irq = (int)(uint64_t)data;
    if(!get_arm_v7m_is_handler_mode())
    {
        if(mem_access_trigger_irq_times_count[irq] > mem_access_trigger_irq_times[irq])
        {
            insert_irq = insert_nvic_intc(irq);
            mem_access_trigger_irq_times_count[irq] = 0;
            if(insert_irq)
                simple_log(flog,false,"nostop_watchpoint_exec_mem",irq,vaddr,0);
            
        }
        else
        {
             mem_access_trigger_irq_times_count[irq] ++;
        }

    }
}
void nostop_watchpoint_exec_func(hwaddr vaddr,hwaddr len,uint32_t val,void *data)
{
    if(val == 0)
        return;
    int irq = (int)(uint64_t)data;
    int func_val_index = 0;

    uint32_t *func_val_arrays = irq_models[irq].func_vals;


    while(func_val_arrays[func_val_index]!= 0 )
    {

        if(func_val_arrays[func_val_index] == val)
        {
            return;
        }
        func_val_index++;
    }
    func_val_arrays[func_val_index] = val;

    model_irq(irq);
}

bool arm_cpu_do_interrupt_hook(int32_t exec_index)
{  
    

    full_log(flog,"arm_cpu_do_interrupt_hook",exec_index,0,0);
    
    if(exec_index == EXCP_SWI || exec_index == EXCP_IRQ || exec_index == EXCP_EXCEPTION_EXIT)
    {
        return true;
    }
    

    bool pc_changed;
    prepare_exit(EXIT_CRASH,0,get_arm_pc(),num_mmio,0);
    pc_changed = exit_with_code_start();
    return false;
}


void enable_nvic_hook(int irq)
{
    
    simple_log(flog,false,"enable_nvic_hook",irq,0,0);


    if(!dumped_irq[irq] && irq > ARMV7M_EXCP_SYSTICK)
    {
        dumped_irq[irq] = true;
        model_irq(irq);
    }
}
void post_thread_exec(int exec_ret)
{
    
    bool pc_changed;

    simple_log(flog,false,"post_thread_exec",exec_ret,0,0);

    prepare_exit(EXIT_TIMEOUT,0,get_arm_pc(),num_mmio,0);
    pc_changed = exit_with_code_start();

}

//////////////////////////////////////////////////snapshot below
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

    id_str = getenv(SHM_SHARE_FUZZ_QUEUE_VAR);
    if (id_str) {
    uint32_t shm_id = atoi(id_str);
    __afl_share_fuzz_queue_data = shmat(shm_id, NULL, 0);
    if (__afl_share_fuzz_queue_data == (void *)-1) _exit(1);
    }

    queue = (struct fuzz_queue *)__afl_share_fuzz_queue_data;
}






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


bool exec_bbl_snapshot(hwaddr pc,uint32_t id)
{
    int i;
    static bool returned = false;
    bool pc_changed;
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

        prepare_exit(EXIT_FORKSRV_UP,0,0,0,0);
        pc_changed = exit_with_code_start();

        return pc_changed;
    }
    else if(snapshot_point && !returned)
    {
       
        arm_restore_snapshot(org_snap);
        returned = true;
        return true;
    }
    simple_log(flog,false,"snapshot bbl",0,0,0);

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
    memset(irq_models,0,sizeof(struct IRQ_MODEL) * NVIC_MAX_VECTORS);
    __afl_map_shm();

}

int run_config()
{
    int i = 0;

    struct XXSimulator *simulator;
    simulator = create_simulator(ARM_CORTEX_M,false);
    init_simulator(simulator);
    if(config->vecbase)
        set_armv7_vecbase(config->vecbase);
    

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
    org_snap = arm_take_snapshot();
    register_exec_bbl_hook(exec_bbl_snapshot);
    model_irq(ARMV7M_EXCP_SYSTICK);
    model_all_infinite_loop();
    enable_nostop_watchpoint();
    exec_simulator(simulator);
    return 1;
}
