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
#include "fuzzer.h"
#include "config.h"
#include "irq.h"
#include "model.h"
#include "snapshot.h"
#include "stream.h"
#include "log.h"
#include "simulator.h"

//#define DBG
#define CRASH_DBG


int mode;

SIMULATOR_CONFIG* config;



uint8_t *__afl_share_fuzz_queue_data;
uint8_t *__afl_share_stream_data;
uint8_t *__afl_area_ptr;
// uint32_t __afl_prev_loc;


int fd_to_fuzzer, fd_from_fuzzer;

FILE *flog;
FILE *f_crash_log;
FILE *f_irq_log;


uint64_t nommio_executed_bbls;
uint64_t max_bbl_exec;


EXIT_INFO exit_info;
bool next_bbl_should_exit = false;


uint32_t run_index;

char *dump_dir;
char *model_dir;
char *log_dir;
char *fuzzware_config_filename;

bool use_fuzzware = true;


extern ARMM_SNAPSHOT *org_snap,*new_snap;



bool exit_with_code_start()
{
    bool pc_changed;
    int bytes_received;
    CMD_INFO cmd_info;

    

    #ifdef DBG
    fprintf(flog,"%d->exit pc:%x %s\n",run_index,get_arm_pc(),get_fuzz_exit_name(exit_info.exit_code));
    #endif

    write(fd_to_fuzzer , &exit_info,sizeof(EXIT_INFO));   
    do
    {

        bytes_received  = read(fd_from_fuzzer,&cmd_info,sizeof(CMD_INFO)); 

    } while (bytes_received != sizeof(CMD_INFO));
    

    
    
    if(unlikely(cmd_info.cmd == CMD_TERMINATE))
    {
        printf("received terminate cmd from fuzzer\n");
        terminate_simulation();
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
        terminate_simulation();
        pc_changed = true;
    }
    if(pc_changed)
    {
        arm_restore_snapshot(new_snap);
        nommio_executed_bbls = 0;
        run_index++;
        irq_on_new_run();
        collect_streams();
    }
    return pc_changed;
     
}

void prepare_exit(uint32_t exit_code,uint32_t exit_pc, uint32_t exit_lr, uint32_t exit_stream_id, uint32_t exit_mmio_addr ,uint32_t mmio_len)
{
    
    exit_info.exit_code = exit_code;
    exit_info.exit_pc = exit_pc;
    exit_info.exit_lr = exit_lr;

    exit_info.stream_info.exit_stream_id = exit_stream_id;
    exit_info.stream_info.exit_mmio_addr = exit_mmio_addr;
    exit_info.stream_info.mmio_len = mmio_len;

}




uint64_t mmio_read_common(void *opaque,hw_addr addr,unsigned size)
{
    uint64_t ret = 0;
    if(next_bbl_should_exit)
        return ret;

    addr = (hw_addr)(uint64_t)opaque + addr;
    uint64_t precise_pc = get_arm_precise_pc();
    
    int stream_status;
    bool pc_changed;

    uint32_t stream_id = hash_32_ext(addr) ^ hash_32_ext(precise_pc) ;
    
    SHARED_STREAM * stream =  get_stream(stream_id);


    if(!stream->avaliable)
    {
        if(mode == MODE_FUZZ)
        {
            if(!stream->dumped)
            {
                stream->dumped = true;
                if(use_fuzzware)
                    dump_state(stream_id,MMIO_STATE_PREFIX,dump_dir);
                
            }

            prepare_exit(EXIT_FUZZ_STREAM_NOTFOUND,precise_pc,0,stream_id,addr,size);

            exit_with_code_start();

            if(!stream->avaliable)
            {
                printf("stream not added by fuzzer id:%x\n",stream_id);
                exit(0);
                return ret;
            }
        }
        else
        {
            #ifdef DBG
            fprintf(flog,"stream not added by fuzzer id:%x\n",stream_id);
            #endif
            prepare_exit(EXIT_DBG_STREAM_NOTFOUND,precise_pc,0,stream_id,addr,size);
            next_bbl_should_exit = true;
            return ret;
        }
        
    }

    stream_status = get_stream_status(stream);
       
    if(likely(stream_status == STREAM_STATUS_OK))
    {
        get_fuzz_data(stream, &ret);  
    }
    else if(stream_status == STREAM_STATUS_OUTOF)
    {
        prepare_exit(EXIT_FUZZ_OUTOF_STREAM,precise_pc,0,stream_id,addr,size);
        next_bbl_should_exit = true;
    }
    else
    {

    }

    #ifdef DBG
    fprintf(flog,"%d->mmio read pc:%x mmio_addr:%x mmio_value:%x mmio_id:%x\n",run_index,get_arm_precise_pc(),addr,(reg_val)ret,stream_id);
    #endif
    
    return ret;
}

void mmio_write_common(void *opaque,hw_addr addr,uint64_t data,unsigned size)
{
    
}


bool arm_exec_bbl(hw_addr pc,uint32_t id)
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
        prepare_exit(EXIT_FUZZ_TIMEOUT);
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
    
    #ifdef DBG
    fprintf(flog,"%d->bbl pc:%x\n",run_index,pc);
    #endif
    __afl_area_ptr[id] ++;
    nommio_executed_bbls++;

    return pc_changed;
}

void insert_idel_irq()
{
    irq_on_idel();

}
void enable_arm_intc()
{
    irq_on_idel();
}

void nostop_watchpoint_exec_overwrite_vec(hw_addr vaddr,hw_addr len,uint32_t val, void *data)
{
    
    int irq = (int)(uint64_t)data;
    irq_on_overwrite_vec_entry(irq,vaddr);
}
void nostop_watchpoint_exec_mem(hw_addr vaddr,hw_addr len,uint32_t val, void *data)
{
    int irq = (int)(uint64_t)data;
    irq_on_mem_access(irq,vaddr);
}
void nostop_watchpoint_exec_unresolved_func_ptr(hw_addr vaddr,hw_addr len,uint32_t val,void *data)
{
    int irq = (int)(uint64_t)data;
    irq_on_unsolved_func_ptr_write(irq, vaddr, val);

}


void on_set_nvic_vecbase(uint32_t addr, int secure)
{
    if(secure)
        return;
    irq_on_set_new_vecbase(addr);
}
void enable_nvic(irq_val irq)
{
    irq_on_enable_nvic_irq(irq);
}
void disenable_nvic(irq_val irq)
{
    irq_on_disable_nvic_irq(irq);
}

bool arm_exec_loop_bbl(hw_addr pc,uint32_t id)
{
    insert_idel_irq();
    return false;
}
bool arm_cpu_do_interrupt_hook(int32_t exec_index)
{  
    #ifdef DBG
    fprintf(flog,"%d->arm_cpu_do_interrupt pc:%x %s  ",run_index,get_arm_pc(),get_arm_intc_name(exec_index));
    append_full_ctx_string(flog);
    fprintf(flog,"\n");
    #endif

    if(exec_index != EXCP_PREFETCH_ABORT && exec_index != EXCP_DATA_ABORT && exec_index != EXCP_HYP_TRAP && exec_index != EXCP_BKPT)
    {
        return true;
    }
    if(exec_index == EXCP_BKPT)
    {
        prepare_exit(EXIT_FUZZ_BKP,get_arm_pc(),get_arm_lr(),0,0,0);
        exit_with_code_start();
        return false;
    }

    #ifdef CRASH_DBG
    fprintf(f_crash_log,"%d->crash ",run_index);
    append_full_ctx_string(f_crash_log);
    fprintf(f_crash_log,"\n");
    #endif

    prepare_exit(EXIT_FUZZ_CRASH,get_arm_pc(),get_arm_lr(),0,0,0);
    exit_with_code_start();
    
    return false;
}
void post_thread_exec(int exec_ret)
{
    
    bool pc_changed;

    #ifdef DBG
    fprintf(flog,"%d->post_thread_exec pc:%x %s\n",run_index,get_arm_pc(),get_qemu_exit_name(exec_ret));
    #endif

    if(exec_ret == EXCP_HLT || exec_ret == EXCP_HALTED)
        insert_idel_irq();
    else if(exec_ret == EXCP_INTERRUPT)
    {
        prepare_exit(EXIT_FUZZ_EXCP_INTERRUPT);
        pc_changed = exit_with_code_start();
    }
    else if(exec_ret == EXCP_DEBUG)
    {
        prepare_exit(EXIT_FUZZ_EXCP_DEBUG);
        pc_changed = exit_with_code_start();
    }
    else if(exec_ret == EXCP_YIELD)
    {
        prepare_exit(EXIT_FUZZ_EXCP_YIELD);
        pc_changed = exit_with_code_start();
    }
    else if(exec_ret == EXCP_ATOMIC)
    {
        prepare_exit(EXIT_FUZZ_EXCP_ATOMIC);
        pc_changed = exit_with_code_start();
    }

}
void mem_access_log(hw_addr vaddr,uint32_t val,uint32_t flag)
{
    fprintf(flog,"%d->memory access pc:%x addr:%x value:%x flag:%d\n",run_index,get_arm_pc(),vaddr,val,flag);
}

//-----------------------------------------------------------
void __afl_map_shm(void) {

    char *id_str = getenv(SHM_ENV_VAR);
    if (id_str) {
    uint32_t shm_id = atoi(id_str);
    __afl_area_ptr = (uint8_t *)shmat(shm_id, NULL, 0);
    if (__afl_area_ptr == (void *)-1) _exit(1);
    }

    id_str = getenv(SHM_SHARE_STREAM_VAR);
    if (id_str) {
    uint32_t shm_id = atoi(id_str);
    __afl_share_stream_data = (uint8_t *)shmat(shm_id, NULL, 0);
    if (__afl_share_stream_data == (void *)-1) _exit(1);
    }

    id_str = getenv(SHM_SHARE_FUZZ_QUEUE_VAR);
    if (id_str) {
    uint32_t shm_id = atoi(id_str);
    __afl_share_fuzz_queue_data = (uint8_t *)shmat(shm_id, NULL, 0);
    if (__afl_share_fuzz_queue_data == (void *)-1) _exit(1);
    }

    set_queue_addr(__afl_share_fuzz_queue_data);

}

void print_stacktrace()
{
#define MAX_STACK_LEVELS 50
  void *buffer[MAX_STACK_LEVELS];
  int levels = backtrace(buffer, MAX_STACK_LEVELS);

  backtrace_symbols_fd(buffer + 1, levels - 1, 2);
}
void cleanup()
{
    shmdt(__afl_area_ptr);
    shmdt(__afl_share_stream_data);
    shmdt(__afl_share_fuzz_queue_data);
}
void terminate_simulation()
{
    cleanup();
    prepare_exit(EXIT_CTL_TERMINATE);
    write(fd_to_fuzzer , &exit_info,sizeof(EXIT_INFO));  //forkserver up
    while (1)
    {
        ;
    }
    
}






static void segv_exit(int signal)
{
    printf("segmentation fault\n");
    print_stacktrace();
    terminate_simulation();
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
    terminate_simulation();
  }
  if (signal(SIGABRT, segv_exit) == SIG_ERR) 
  {
    printf("Error setting signal handler");
    terminate_simulation();
  }
  
}

void init_log()
{
    char path_buffer[PATH_MAX];
    sprintf(path_buffer,"%s/simulator_log.txt",log_dir);
    flog = fopen(path_buffer,"w");
    sprintf(path_buffer,"%s/simulator_crash.txt",log_dir);
    f_crash_log = fopen(path_buffer,"w");
    sprintf(path_buffer,"%s/simulator_irq.txt",log_dir);
    f_irq_log = fopen(path_buffer,"w");

    setbuf(flog,0);
    setbuf(f_crash_log,0);
    setbuf(f_irq_log,0);
}
void init(int argc, char **argv)
{
    int opt;
    while ((opt = getopt(argc, argv, "c:d:m:l:f:t:sb:a:n")) != -1) 
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
        case 'b':
            max_bbl_exec = atoi(optarg);
            break;
        case 'a':
            mode = atoi(optarg);
            break;
        case 'n':
            use_fuzzware = false;
            break;

            
        default: /* '?' */
            printf("Usage error\n");
            terminate_simulation();
        }
    }
    if(!config)
    {
        printf("generate config error\n");
        terminate_simulation();
    }
        
    irq_on_init();
    init_log();
    init_signal_handler();
    init_streams();
    __afl_map_shm();

}

int run_config()
{
    int i = 0;
    XXSimulator *simulator;
    simulator = create_simulator(false);
    init_simulator(simulator);
    set_armv7_init_vecbase(config->vecbase);
        
    

    for(auto it = config->segs->begin(); it!= config->segs->end(); it++)
    {
        if((*it)->type == SEG_RAM)
        {
            add_ram_region((*it)->name,
            (*it)->start, 
            (*it)->size,
            (*it)->readonly);
            zero_ram((*it)->start,(*it)->size);
            for(auto it2 = (*it)->contents->begin(); it2 != (*it)->contents->end(); it2++)
            {
                load_file_ram((*it2)->file,
                (*it)->start, 
                (*it2)->file_offset, 
                (*it2)->mem_offset, 
                (*it2)->file_size);
            }
        }
        else if((*it)->type == SEG_MMIO)
        {
            add_mmio_region((*it)->name,(*it)->start, (*it)->size, mmio_read_snapshot, mmio_write_snapshot,(void*)(uint64_t)(*it)->start);
        }
    }

    reset_arm_reg();

    org_snap = arm_take_snapshot();

    register_armm_ppb_default_read_hook(mmio_read_common);
    register_armm_ppb_default_write_hook(mmio_write_common);
    register_exec_bbl_hook(exec_bbl_snapshot);
    register_do_arm_interrupt_hook(arm_cpu_do_interrupt_hook);
    register_mem_access_log_hook(mem_access_log);
    register_set_nvic_vecbase_hook(on_set_nvic_vecbase);
    register_enable_arm_interrupt_hook(enable_arm_intc);
    register_enable_nvic_hook(enable_nvic);
    register_disable_nvic_hook(disenable_nvic);

    register_post_thread_exec_hook(post_thread_exec);
    
    model_all_infinite_loop();

    irq_on_new_run();
    
        

    exec_simulator(simulator);
    return 1;
}
