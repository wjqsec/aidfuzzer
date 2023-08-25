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

uint16_t *__afl_area_ptr;
// uint32_t __afl_prev_loc;


int fd_to_fuzzer, fd_from_fuzzer;

FILE *flog;
FILE *f_crash_log;


uint64_t nommio_executed_bbls;
uint64_t max_bbl_exec = MAX_BBL_EXEC;


struct EXIT_INFO exit_info;
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



void prepare_exit(uint32_t code,uint32_t stream_id,uint64_t pc,uint32_t num_mmio);


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
        printf("stream index colission id:%x\n",metadata->stream_id);
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


void terminate()
{

    shmdt(__afl_area_ptr);
    shmdt(__afl_share_stream_data);
    shmdt(__afl_share_fuzz_queue_data);
    prepare_exit(EXIT_TERMINATE,0,0,0);
    write(fd_to_fuzzer , &exit_info,sizeof(struct EXIT_INFO));  //forkserver up
    while (1)
    {
        ;
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
        num_mmio = 0;
        nommio_executed_bbls = 0;
        run_index++;
        memset(mem_access_trigger_irq_times_count, 0, NVIC_MAX_VECTORS * sizeof(mem_access_trigger_irq_times_count[0]));
        arm_restore_snapshot(new_snap);
        collect_streams();
        pc_changed = true;
    }
    else
    {
        printf("invlaid cmd\n");
        exit(0);
        pc_changed = true;
    }
    #ifdef DBG
    if(pc_changed)
        fprintf(flog,"%d->exit_code = %x pc = %x\n",run_index, exit_info.exit_code,(uint32_t)exit_info.exit_pc);
    else
        fprintf(flog,"%d->continue_code = %x pc = %x\n",run_index, exit_info.exit_code,(uint32_t)exit_info.exit_pc);
    #endif
    return pc_changed;
     
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
void prepare_exit(uint32_t code,uint32_t stream_id,uint64_t pc,uint32_t num_mmio)
{
    exit_info.exit_code = code;
    exit_info.exit_stream_id = stream_id;
    exit_info.exit_pc = pc;
    exit_info.num_mmio = num_mmio;
}

bool get_fuzz_data(struct SHARED_STREAM * stream, uint64_t *out)
{
    bool outofstream = false;
    if( stream->metadata->len >= stream->metadata->element_size + *stream->used && 
        stream->metadata->len < (stream->metadata->element_size * 2) + *stream->used
    )
        outofstream = true;
    
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
    return outofstream;

}

uint64_t mmio_read_common(void *opaque,hwaddr addr,unsigned size)
{
    uint64_t ret = 0;
    addr = (hwaddr)opaque + addr;
    uint64_t precise_pc = get_arm_precise_pc();
    
    bool outofseed;
    bool pc_changed;

    uint32_t stream_id = hash_32_ext(addr) ^ hash_32_ext(precise_pc) ;
    uint32_t index = stream_id % NUM_QUEUE_STREAMS;
    struct SHARED_STREAM * stream =  streams[index];


    if(!stream->avaliable)
    {
        
        if(!stream->dumped)
        {
            dump_state(stream_id,true,MMIO_STATE_PREFIX,dump_dir);
            stream->dumped = true;
        }
            
        prepare_exit(EXIT_STREAM_NOTFOUND,stream_id,precise_pc,num_mmio);
        exit_with_code_start();
        if(!stream->avaliable)
        {
            printf("stream not added by fuzzer\n");
            exit(0);
        }
    }
    
    outofseed = get_fuzz_data(stream, &ret);     
    if(outofseed)
    {
        prepare_exit(EXIT_OUTOFSTREAM,stream_id,precise_pc,num_mmio);
        pc_changed = exit_with_code_start();
        if(pc_changed)
            mmio_exit_cpu_loop();
            
    }
        



    #ifdef DBG
    struct ARM_CPU_STATE state;
    get_arm_cpu_state(&state);
    fprintf(flog,"%d->mmio read pc:%x mmio_addr:%x val:%x stream_id:%x\n",run_index, (uint32_t)get_arm_precise_pc(),(uint32_t)addr,(uint32_t)ret,stream_id);
    #endif

    #ifdef MMIO_READ_DBG
    fprintf(flog,"%d->mmio read pc:%x mmio_addr:%x val:%x stream_id:%x\n",run_index, (uint32_t)get_arm_precise_pc(),(uint32_t)addr,(uint32_t)ret,stream_id);
    #endif
    return ret;
}

void mmio_write_common(void *opaque,hwaddr addr,uint64_t data,unsigned size)
{
    
    #ifdef DBG
    
    addr = (hwaddr)opaque + addr;
    uint64_t precise_pc = get_arm_pc();
    uint32_t stream_id = hash_32_ext(addr) ^ hash_32_ext(precise_pc) ;
    fprintf(flog,"%d->mmio write pc:%x mmio_addr:%x val:%x stream_id:%x\n",run_index, (uint32_t)get_arm_pc(),(uint32_t)addr,(uint32_t)data,stream_id);
    #endif
}


bool arm_exec_bbl(hwaddr pc,uint32_t id,int64_t bbl)
{
    bool pc_changed = false;
    if(unlikely(nommio_executed_bbls >= max_bbl_exec))
    {

        prepare_exit(EXIT_TIMEOUT,0,pc,num_mmio);
        pc_changed = exit_with_code_start();
        return pc_changed;
    }
    
    #ifdef ENABLE_ROUNDROBIN_IRQ
    if(*num_irqs && (bbl % ROUNDROBIN_IRQ_BBLS) == 0)
    {
        insert_nvic_intc(irqs[tmp % (*num_irqs)],false);
        #ifdef DBG
        fprintf(flog,"insert irq %d\n",irqs[tmp % (*num_irqs)]);
        #endif

    }
    #endif


    // __afl_area_ptr[id ^ __afl_prev_loc] ++;
    // __afl_prev_loc = id >> 1;
    
    __afl_area_ptr[id] ++;
    nommio_executed_bbls++;
    #ifdef DBG
    fprintf(flog,"%d->bbl pc:%x\n",run_index, (uint32_t)pc);
    #endif
    
    
    return pc_changed;
}
bool arm_exec_loop_bbl(hwaddr pc,uint32_t id,int64_t bbl)
{
    bool insert_irq;
    insert_irq = insert_nvic_intc(ARMV7M_EXCP_SYSTICK);
    #ifdef DBG
    if(insert_irq)
        fprintf(flog,"%d->arm_exec_loop_bbl insert irq:%d pc:%x\n",run_index,ARMV7M_EXCP_SYSTICK,(uint32_t)pc);
    #endif
    
    for(int i=0; i<num_do_mmio_irqs ; i++)
    {
        insert_irq = insert_nvic_intc(do_mmio_irqs[i]);
        #ifdef DBG
        if(insert_irq)
            fprintf(flog,"%d->arm_exec_loop_bbl insert irq:%d pc:%x\n",run_index,do_mmio_irqs[i],(uint32_t)pc);
        #endif
    }
    return false;
}
void arm_exec_func_dummy(uint64_t pc,uint64_t *return_val)
{

}
void nostop_watchpoint_exec(hwaddr vaddr,hwaddr len,void *data)
{
    bool insert_irq;
    int irq = (int)(uint64_t)data;
    if(!get_arm_v7m_is_handler_mode())
    {
        if(mem_access_trigger_irq_times_count[irq] > mem_access_trigger_irq_times[irq])
        {
            insert_irq = insert_nvic_intc(irq);
            mem_access_trigger_irq_times_count[irq] = 0;
            #ifdef DBG
            if(insert_irq)
                fprintf(flog,"%d->nostop_watchpoint_exec insert irq:%d pc:%x stopwatch hit addr:%x\n",run_index,irq,(uint32_t)get_arm_pc(),(uint32_t)vaddr);
            #endif
        }
        else
        {
             mem_access_trigger_irq_times_count[irq] ++;
        }
        
        
       
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
    fprintf(f_crash_log,"%d->crash index:%d pc:%x  r0:%x, r1:%x, r2:%x, r3:%x, r4:%x r5:%x r6:%x r7:%x r8:%x r9:%x r10:%x r11:%x ip:%x sp:%x lr:%x [sp]=%x, [sp+4]=%x [sp+8]=%x\n",
    run_index,
    exec_index,
    state.regs[15], 
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
    state.regs[13],
    state.regs[14], 
    sp0, 
    sp1,
    sp2);
    #endif
    #ifdef DBG

    fprintf(f_crash_log,"%d->crash index:%d pc:%x  r0:%x, r1:%x, r2:%x, r3:%x, r4:%x r5:%x r6:%x r7:%x r8:%x r9:%x r10:%x r11:%x ip:%x sp:%x lr:%x [sp]=%x, [sp+4]=%x [sp+8]=%x\n",
    run_index,
    exec_index,
    state.regs[15], 
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
    state.regs[13],
    state.regs[14], 
    sp0, 
    sp1,
    sp2);
    #endif
    #endif
    bool pc_changed;
    prepare_exit(EXIT_CRASH,0,get_arm_pc(),num_mmio);
    pc_changed = exit_with_code_start();
    return false;
}


void enable_nvic_hook(int irq)
{
    return;
    char state_filename[PATH_MAX];
    char model_filename[PATH_MAX];
    char cmd[PATH_MAX];
    char line[PATH_MAX];
    char *addr_size_ptr;
    struct ARM_CPU_STATE state;
    FILE *f;
    
    
    #ifdef DBG
    fprintf(flog,"%d->enable irq:%d pc:%x\n",run_index, irq,(uint32_t)get_arm_pc());
    #endif


    if(!dumped_irq[irq])
    {
        dumped_irq[irq] = true;

        sprintf(state_filename,"%s/%s%08x",dump_dir,IRQ_STATE_PREFIX,irq);
        sprintf(model_filename,"%s/%s",model_dir,IRQ_MODEL_FILENAME);

        // if(access(model_filename,F_OK) != 0)
        // {

            dump_state(irq,false,IRQ_STATE_PREFIX,dump_dir);
            printf("pc:%x  ",(uint32_t)get_arm_pc());
            sprintf(cmd,"python3 ../../dataflow_modelling/irq_model.py -m %s -s %s -i 0x%x -o %s -c %s > /dev/null 2>&1","irq",state_filename,irq,model_filename,fuzzware_config_filename);
            puts(cmd);
            system(cmd);
            puts("model done");
        // }
        

        
        f = fopen(model_filename,"r");
        
        bool start = false;
        bool do_mmio_irq = false;
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
            insert_nostop_watchpoint(addr,len,QEMU_PLUGIN_MEM_RW_ ,nostop_watchpoint_exec,(void*)(uint64_t)irq);
            mem_access_trigger_irq_times[irq]++;
            do_mmio_irq = true;
            printf("insert_nostop_watchpoint irq:%d addr:%x\n",irq,addr);
        }
        if(do_mmio_irq)
            do_mmio_irqs[num_do_mmio_irqs++] = irq;
        fclose(f);
        
        
    }

    
}
void post_thread_exec(int exec_ret)
{
    struct ARM_CPU_STATE state;
    bool pc_changed;
    #ifdef DBG

    get_arm_cpu_state(&state);
    fprintf(flog,"%d->post thread exec:%d  pc:%x\n",run_index, exec_ret,state.regs[15]);
    #endif

    prepare_exit(EXIT_TIMEOUT,0,get_arm_pc(),num_mmio);
    pc_changed = exit_with_code_start();

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
        
        prepare_exit(EXIT_FORKSRV_UP,0,0,0);
        pc_changed = exit_with_code_start();

        return pc_changed;
    }
    else if(snapshot_point && !returned)
    {
       
        arm_restore_snapshot(org_snap);
        returned = true;
        return true;
    }
    #ifdef DBG
    fprintf(flog,"snapshot bbl:%x\n", (uint32_t)pc);
    #endif
    __afl_area_ptr[id] ++;

    return false;
}

void get_all_infinite_loop()
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
    enable_nvic_hook(ARMV7M_EXCP_SYSTICK);
    get_all_infinite_loop();
    enable_nostop_watchpoint();
    exec_simulator(simulator);
    return 1;
}
