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
#include <string>
#include <clipp.h>
#include <glib.h>
#include <set>
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
#include "cov.h"

using namespace std;
using namespace clipp;
//#define DBG
#define CRASH_DBG



SIMULATOR_CONFIG* config;



uint8_t *__afl_share_fuzz_queue_data;
uint8_t *__afl_share_stream_data;
FUZZ_COVERAGE_ELEMENT_TYPE *__afl_area_ptr;
// uint32_t __afl_prev_loc;


int fd_to_fuzzer, fd_from_fuzzer;

FILE *flog;
FILE *f_crash_log;
FILE *f_irq_log;

uint64_t nommio_executed_bbls;
uint64_t max_bbl_exec;
uint64_t infinite_loop_exec;


EXIT_INFO exit_info;
bool next_bbl_should_exit = false;

uint32_t crash_times = 0;

uint32_t run_index;

std::set<hw_addr> total_unique_bbls;

string dump_dir;
string model_dir;
string log_dir;
string fuzzware_config_filename;
string cov_log;
string cov_filter;



extern ARMM_SNAPSHOT *org_snap,*new_snap;



#ifdef ROUND_ROBIN
uint64_t bbls;
#endif

CMD_INFO exit_with_code_get_cmd()
{
    int bytes_received;
    CMD_INFO cmd_info;

    #ifdef DBG
    fprintf(flog,"%d->exit pc:%x %s\n",run_index,get_arm_pc(),get_fuzz_exit_name(exit_info.exit_code));
    #endif

    exit_info.unique_bbls = total_unique_bbls.size();
    write(fd_to_fuzzer , &exit_info,sizeof(EXIT_INFO));   
    do
    {

        bytes_received  = read(fd_from_fuzzer,&cmd_info,sizeof(CMD_INFO)); 

    } while (bytes_received != sizeof(CMD_INFO));
   
    
    if(unlikely(cmd_info.cmd == CMD_TERMINATE))
    {
        if (cov_log != "")
            dump_coverage(cov_log.c_str());
        printf("received terminate cmd from fuzzer\n");
        terminate_simulation();
    }

    return cmd_info;
     
}
void start_new()
{
    arm_restore_snapshot(new_snap);
    nommio_executed_bbls = 0;
    infinite_loop_exec = 0;
    run_index++;
    
    collect_streams();

    #ifndef ROUND_ROBIN
    irq_on_new_run();
    #endif

    #ifdef ROUND_ROBIN
    bbls = 1;
    #endif
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
    CMD_INFO cmd_info;
    if(next_bbl_should_exit)
        return ret;

    addr = (hw_addr)(uint64_t)opaque + addr;
    uint64_t precise_pc = get_arm_precise_pc();
    
    int stream_status;

    uint32_t stream_id = hash_32_ext(addr) ^ hash_32_ext(precise_pc) ;
    
    SHARED_STREAM * stream =  get_stream(stream_id);


    if(!stream->avaliable)
    {
        static int num_dumped = 0;
        if(!stream->dumped && num_dumped < (MAX_FUZZWARE_MODEL + 10))
        {
            num_dumped++;
            stream->dumped = true;
            dump_state(stream_id,MMIO_STATE_PREFIX);
            
        }

        prepare_exit(EXIT_FUZZ_STREAM_NOTFOUND,precise_pc,0,stream_id,addr,size);
        cmd_info = exit_with_code_get_cmd();
        if (cmd_info.cmd == CMD_CONTINUE_ADD_STREAM)
        {
            add_stream(cmd_info.added_stream_index);
            if(!stream->avaliable)
            {
                printf("stream not added by fuzzer id:%x\n",stream_id);
                terminate_simulation();
                return ret;
            }
        }
        else if(cmd_info.cmd == CMD_FUZZ)
        {
            prepare_exit(EXIT_DBG_STREAM_NOTFOUND,precise_pc,0,stream_id,addr,size);
            next_bbl_should_exit = true;
            return ret;
        }
        else
        {
            printf("cmd %d after stream not found not support\n",cmd_info.cmd);
            terminate_simulation();
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
        cmd_info = exit_with_code_get_cmd();
        if (cmd_info.cmd == CMD_FUZZ)
        {
            next_bbl_should_exit = true;
        }
        else
        {
            printf("cmd %d after stream outof not support\n",cmd_info.cmd);
            terminate_simulation();
        }
        
    }
    else
    {
        printf("stream status %d not found\n",stream_status);
        terminate_simulation();
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
    CMD_INFO cmd_info;

    if(unlikely(next_bbl_should_exit))
    {
        next_bbl_should_exit = false;
        start_new();
        return true;
    }

    if(unlikely(nommio_executed_bbls >= max_bbl_exec))
    {
        prepare_exit(EXIT_FUZZ_TIMEOUT);
        cmd_info = exit_with_code_get_cmd();
        if(cmd_info.cmd == CMD_FUZZ)
        {
            start_new();
            return true;
        }
        else
        {
            printf("cmd %d after timeout not support\n",cmd_info.cmd);
            terminate_simulation();
        }
    }
    
    
    #ifdef ROUND_ROBIN
    if ((bbls % ROUNDROBIN_IRQ_BBLS) == 0)
    {
        uint32_t stream_id = IRQ_STREAM_ID;
        uint64_t ret = 0;
        SHARED_STREAM * stream =  get_stream(stream_id);
        if(!stream->avaliable)
        {

            prepare_exit(EXIT_FUZZ_STREAM_NOTFOUND,pc,0,stream_id,0,1);
            cmd_info = exit_with_code_get_cmd();
            if (cmd_info.cmd == CMD_CONTINUE_ADD_STREAM)
            {
                add_stream(cmd_info.added_stream_index);
                if(!stream->avaliable)
                {
                    printf("stream not added by fuzzer id:%x\n",stream_id);
                    terminate_simulation();
                    return true;
                }
            }
            else if(cmd_info.cmd == CMD_FUZZ)
            {
                start_new();
                return true;
            }
            else
            {
                printf("cmd %d after stream not found not support\n",cmd_info.cmd);
                terminate_simulation();
            }
        }

        int stream_status = get_stream_status(stream);
       
        if(likely(stream_status == STREAM_STATUS_OK))
        {
            get_fuzz_data(stream, &ret);  
        }
        else if(stream_status == STREAM_STATUS_OUTOF)
        {
            prepare_exit(EXIT_FUZZ_OUTOF_STREAM,pc,0,stream_id,0,0);
            cmd_info = exit_with_code_get_cmd();
            if (cmd_info.cmd == CMD_FUZZ)
            {
                start_new();
                return true;
            }
            else
            {
                printf("cmd %d after stream outof not support\n",cmd_info.cmd);
                terminate_simulation();
            }
            
        }
        else
        {
            printf("stream status %d not found\n",stream_status);
            terminate_simulation();
        }


        irq_val *irqs;
        irq_val num_irqs =  get_enabled_nvic_irq(&irqs);
        int index = ret % (num_irqs - ARMV7M_EXCP_SYSTICK + 1);

        bool insert  = insert_nvic_intc(irqs[index + ARMV7M_EXCP_SYSTICK -1]);
        
        #ifdef DBG
        if(insert)
            fprintf(flog,"%d->insert round robin irq:%d\n",run_index,irqs[index + ARMV7M_EXCP_SYSTICK -1]);
        #endif
    }
    bbls ++;
    #endif



    // __afl_area_ptr[id ^ __afl_prev_loc] ++;
    // __afl_prev_loc = id >> 1;

    #ifdef DBG
    fprintf(flog,"%d->bbl pc:%x  handle:%d  ",run_index,pc,get_arm_v7m_is_handler_mode());
    append_simple_ctx_string(flog);
    fprintf(flog,"\n");
    #endif
    __afl_area_ptr[id] ++;
    nommio_executed_bbls++;

    return false;
}


void wfie_ins()
{
    #ifdef DBG
    fprintf(flog,"%d->wfi/wfe\n",run_index);
    #endif
    irq_on_idel(0);
    return;
}
void enable_arm_intc()
{
    #ifdef DBG
            fprintf(flog,"%d->cpie\n",run_index);
    #endif
    irq_on_idel(NUM_IRQ_CPIE_TIMES);
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
    CMD_INFO cmd_info;
    if(unlikely(infinite_loop_exec >= MAX_INFINITE_LOOP_EXEC))
    {
        prepare_exit(EXIT_FUZZ_TIMEOUT);
        cmd_info = exit_with_code_get_cmd();
        if(cmd_info.cmd == CMD_FUZZ)
        {
            start_new();
            return true;
        }
        else
        {
            printf("cmd %d after timeout not support\n",cmd_info.cmd);
            terminate_simulation();
        }
    }
    infinite_loop_exec++;
    #ifdef DBG
    fprintf(flog,"%d->infinite loop\n",run_index);
    #endif
    irq_on_idel(NUM_IRQ_LOOP_TIMES);
    return false;
}
bool arm_cpu_do_interrupt_hook(int32_t exec_index)
{  
    #ifdef DBG
    fprintf(flog,"%d->arm_cpu_do_interrupt pc:%x %s  ",run_index,get_arm_pc(),get_arm_intc_name(exec_index));
    append_full_ctx_string(flog);
    fprintf(flog,"\n");
    #endif
    CMD_INFO cmd_info;
    if(exec_index != EXCP_PREFETCH_ABORT && exec_index != EXCP_DATA_ABORT && exec_index != EXCP_HYP_TRAP && exec_index != EXCP_BKPT)
    {
        return true;
    }
    if(exec_index == EXCP_BKPT)
    {
        prepare_exit(EXIT_FUZZ_BKP,get_arm_pc(),get_arm_lr(),0,0,0);
        cmd_info = exit_with_code_get_cmd();
        if(cmd_info.cmd == CMD_FUZZ)
        {
            start_new();
        }
        else
        {
            printf("cmd %d after bkp not support\n",cmd_info.cmd);
            terminate_simulation();
        }
        return false;
    }

    #ifdef CRASH_DBG
    if(crash_times < 10000)
    {
        fprintf(f_crash_log,"%d->crash ",run_index);
        append_full_ctx_string(f_crash_log);
        fprintf(f_crash_log,"\n");
        crash_times++;
    }
    
    #endif

    prepare_exit(EXIT_FUZZ_CRASH,get_arm_pc(),get_arm_lr(),0,0,0);
    cmd_info = exit_with_code_get_cmd();
    if(cmd_info.cmd == CMD_FUZZ)
    {
        start_new();
    }
    else
    {
        printf("cmd %d after crash not support\n",cmd_info.cmd);
        terminate_simulation();
    }
    
    return false;
}
void post_thread_exec(int exec_ret)
{
    CMD_INFO cmd_info;
    #ifdef DBG
    fprintf(flog,"%d->post_thread_exec pc:%x %s\n",run_index,get_arm_pc(),get_qemu_exit_name(exec_ret));
    #endif

    if(exec_ret == EXCP_HLT || exec_ret == EXCP_HALTED)
    {
        #ifdef DBG
            fprintf(flog,"%d->post wfi/wfe\n",run_index);
        #endif
        irq_on_idel(0);
        return;
    }
        
    else if(exec_ret == EXCP_INTERRUPT)
    {
        prepare_exit(EXIT_FUZZ_EXCP_INTERRUPT);
    }
    else if(exec_ret == EXCP_DEBUG)
    {
        prepare_exit(EXIT_FUZZ_EXCP_DEBUG);
    }
    else if(exec_ret == EXCP_YIELD)
    {
        prepare_exit(EXIT_FUZZ_EXCP_YIELD);
    }
    else if(exec_ret == EXCP_ATOMIC)
    {
        prepare_exit(EXIT_FUZZ_EXCP_ATOMIC);
    }
    cmd_info = exit_with_code_get_cmd();
    if(cmd_info.cmd == CMD_FUZZ)
    {
        start_new();
    }
    else
    {
        printf("cmd %d after %s not support\n",cmd_info.cmd,QEMU_EXIT_NAMES[exec_ret - EXCP_INTERRUPT]);
        terminate_simulation();
    }

}

void mem_access_log(hw_addr vaddr,uint32_t val,uint32_t flag)
{
    const char *op = flag == QEMU_PLUGIN_MEM_R_ ? "read" : "write";
    fprintf(flog,"%d->memory %s pc:%x addr:%x value:%x\n",run_index,op,get_arm_precise_pc(),vaddr,val);
}

//-----------------------------------------------------------
void __afl_map_shm(void) {

    char *id_str = getenv(SHM_ENV_VAR);
    if (id_str) {
    uint32_t shm_id = atoi(id_str);
    __afl_area_ptr = (FUZZ_COVERAGE_ELEMENT_TYPE *)shmat(shm_id, NULL, 0);
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
    fclose(flog);
    fclose(f_crash_log);
    fclose(f_irq_log);

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
    sprintf(path_buffer,"%s/simulator_log.txt",log_dir.c_str());
    flog = fopen(path_buffer,"w");
    sprintf(path_buffer,"%s/simulator_crash.txt",log_dir.c_str());
    f_crash_log = fopen(path_buffer,"w");
    sprintf(path_buffer,"%s/simulator_irq.txt",log_dir.c_str());
    f_irq_log = fopen(path_buffer,"a");

    // setbuf(flog,0);
    // setbuf(f_crash_log,0);
    // setbuf(f_irq_log,0);
}

void init(int argc, char **argv)
{
    auto cli = ( 
    value("dump_dir",dump_dir),
    value("model_dir",model_dir),
    value("log_dir",log_dir),
    
    value("fd_from_fuzzer",fd_from_fuzzer),
    value("fd_to_fuzzer",fd_to_fuzzer),

    value("layout",fuzzware_config_filename),

    option("-max_bbl") & value("max bbl timeout",max_bbl_exec) ,
    option("-cov") & value("cov",cov_log),
    option("-filter") & value("filter",cov_filter)
    
    );
    parse(argc, argv, cli);
    config = generate_xx_config(fuzzware_config_filename.c_str());

    if(!config)
    {
        printf("generate config error\n");
        terminate_simulation();
    }
        
    
    init_log();
    init_bbl_filter(&cov_filter);
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
            
            void * p = add_ram_region((*it)->name,
            (*it)->start, 
            (*it)->size,
            (*it)->readonly);
            (*it)->ptr = p;

            zero_ram(p,(*it)->size);

            for(auto it2 = (*it)->contents->begin(); it2 != (*it)->contents->end(); it2++)
            {
                load_file_ram(p,
                (*it2)->file,
                (*it2)->file_offset, 
                (*it2)->mem_offset, 
                (*it2)->file_size,
                (*it)->size);
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
    register_translate_bbl_hook(translate_bbl);
    register_post_thread_exec_hook(post_thread_exec);
    

    #ifndef ROUND_ROBIN
    irq_on_init();
    register_enable_arm_interrupt_hook(enable_arm_intc);
    register_enable_nvic_hook(enable_nvic);
    register_disable_nvic_hook(disenable_nvic);
    register_set_nvic_vecbase_hook(on_set_nvic_vecbase);
    register_wfie_hook(wfie_ins);
    model_all_infinite_loop();

    #endif
    exec_simulator(simulator);
    return 1;
}
