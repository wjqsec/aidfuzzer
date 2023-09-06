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
#include <execinfo.h>
#include "xx.h"
#include "config.h"
#include "fuzzer.h"
#include "simulator.h"

//#define DBG
#define CRASH_DBG



struct SIMULATOR_CONFIG* config;



uint8_t *__afl_share_fuzz_queue_data;
uint8_t *__afl_share_stream_data;

uint8_t *__afl_area_ptr;
// uint32_t __afl_prev_loc;


int fd_to_fuzzer, fd_from_fuzzer;

FILE *flog;
FILE *f_crash_log;


uint64_t nommio_executed_bbls;
uint64_t max_bbl_exec = MAX_BBL_EXEC;


struct EXIT_INFO exit_info;
bool next_bbl_should_exit = false;
uint32_t num_mmio;


uint32_t run_index;

char *dump_dir;
char *model_dir;
char *log_dir;
char *fuzzware_config_filename;


#include "log.h"
#include "model.h"
#include "snapshot.h"
#include "stream.h"




bool exit_with_code_start()
{
    bool pc_changed;
    int bytes_received;
    struct CMD_INFO cmd_info;

    
    simple_log(flog,false,"may continue",exit_info.exit_code,0,0);
    write(fd_to_fuzzer , &exit_info,sizeof(struct EXIT_INFO));   
    do
    {
        bytes_received  = read(fd_from_fuzzer,&cmd_info,sizeof(struct CMD_INFO)); 
    } while (bytes_received != sizeof(struct CMD_INFO));
    
     
    

    if(unlikely(cmd_info.cmd == CMD_TERMINATE))
    {
        printf("receive terminate cmd\n");
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
        terminate();
        pc_changed = true;
    }
    if(pc_changed)
    {
        simple_log(flog,false,"exit",exit_info.exit_code,0,0);
        num_mmio = 0;
        nommio_executed_bbls = 0;
        run_index++;
        reset_irq_models();
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
            terminate();
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

    simple_log(flog,true,"mmio_read",addr,ret,stream_id);

    
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

void insert_idel_irq()
{

    if(get_arm_v7m_is_handler_mode())
        return;
    bool insert_irq;
    for(int i=0; i<num_do_mmio_irqs ; i++)
    {
        if(!is_irq_avaliable(do_mmio_irqs[i]))
            continue;
        simple_log(flog,false,"try insert idel irq",do_mmio_irqs[i],0,0);
        insert_irq = insert_nvic_intc(do_mmio_irqs[i]);
        if(insert_irq)
            simple_log(flog,false,"insert idel irq",do_mmio_irqs[i],0,0);
    }
}
bool arm_exec_loop_bbl(hwaddr pc,uint32_t id)
{
    insert_idel_irq();
    return false;
}


void nostop_watchpoint_exec_mem(hwaddr vaddr,hwaddr len,uint32_t val, void *data)
{
    bool insert_irq;
    int irq = (int)(uint64_t)data;

    if(get_arm_v7m_is_handler_mode())
        return;
    if(!is_irq_avaliable(irq))
        return;
    

    if(irq_models[irq].mem_access_trigger_irq_times_count > irq_models[irq].mem_access_trigger_irq_times)
    {
        simple_log(flog,false,"try insert mem irq",irq,vaddr,0);
        insert_irq = insert_nvic_intc(irq);
        irq_models[irq].mem_access_trigger_irq_times_count = 0;
        if(insert_irq)
            simple_log(flog,false,"insert mem irq",irq,vaddr,0);
        
    }
    else
    {
        irq_models[irq].mem_access_trigger_irq_times++;
        simple_log(flog,false,"add mem irq count",irq,vaddr,0);
    }
}
void nostop_watchpoint_exec_func(hwaddr vaddr,hwaddr len,uint32_t val,void *data)
{
    if(val == 0)
        return;
    int irq = (int)(uint64_t)data;
    model_irq_after_nullfuncptr_init(irq,val);
    simple_log(flog,false,"model nullptr func",irq,vaddr,0);
}
void nostop_watchpoint_exec_denpendency(hwaddr vaddr,hwaddr len,uint32_t val,void *data)
{
    if(val == 0)
        return;
    int irq = (int)(uint64_t)data;
    solve_irq_dependency(irq, (uint32_t)vaddr);
    simple_log(flog,false,"solve dependency",irq,vaddr,0);
}

bool arm_cpu_do_interrupt_hook(int32_t exec_index)
{  
    full_log(flog,"arm_cpu_do_interrupt_hook",exec_index,0,0);
    if(exec_index != EXCP_PREFETCH_ABORT && exec_index != EXCP_DATA_ABORT && exec_index != EXCP_HYP_TRAP)
    {
        return true;
    }
    

    bool pc_changed;
    prepare_exit(EXIT_CRASH,0,get_arm_pc(),num_mmio,0);
    pc_changed = exit_with_code_start();
    crash_log(f_crash_log,"arm_cpu_do_interrupt_hook",exec_index,0,0);
    return false;
}


void enable_nvic_hook(int irq)
{
    static bool dumped_irq[NVIC_MAX_VECTORS];
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
    if(exec_ret == EXCP_HLT || exec_ret == EXCP_HALTED)
        insert_idel_irq();
    else
    {
        prepare_exit(EXIT_TIMEOUT,0,get_arm_pc(),num_mmio,0);
        pc_changed = exit_with_code_start();
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


void cleanup()
{
    shmdt(__afl_area_ptr);
    shmdt(__afl_share_stream_data);
    shmdt(__afl_share_fuzz_queue_data);
}
void terminate()
{

    cleanup();
    prepare_exit(EXIT_TERMINATE,0,0,0,0);
    write(fd_to_fuzzer , &exit_info,sizeof(struct EXIT_INFO));  //forkserver up
    while (1)
    {
        ;
    }
    
}




void print_stacktrace()
{
#define MAX_STACK_LEVELS 50
  void *buffer[MAX_STACK_LEVELS];
  int levels = backtrace(buffer, MAX_STACK_LEVELS);

  backtrace_symbols_fd(buffer + 1, levels - 1, 2);
}

static void segv_exit(int signal)
{
    printf("segmentation fault\n");
    print_stacktrace();
    terminate();
}
void dummy_sigaction(int signal)
{
    printf("dummy_sigaction\n");
}

void init_signal_handler(void)
{
  if (signal(SIGSEGV, segv_exit) == SIG_ERR) 
  {
    printf("Error setting signal handler");
    exit(0);
  }
  if (signal(SIGABRT, segv_exit) == SIG_ERR) 
  {
    printf("Error setting signal handler");
    exit(0);
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

    init_signal_handler();
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
    {
        set_armv7_vecbase(config->vecbase);
    }
        
    

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
    register_arm_do_interrupt_hook(arm_cpu_do_interrupt_hook);
    model_irq(ARMV7M_EXCP_SYSTICK);
    model_all_infinite_loop();
    enable_nostop_watchpoint();
    exec_simulator(simulator);
    return 1;
}
