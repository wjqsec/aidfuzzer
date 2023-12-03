#ifndef SIMULATOR_INCLUDED
#define SIMULATOR_INCLUDED
#include <stdio.h>
#include <string>
#include "xx.h"
#include "fuzzer.h"
#include "config.h"

using namespace std;
void nostop_watchpoint_exec_mem(hw_addr vaddr,hw_addr len,uint32_t val, void *data);
void nostop_watchpoint_exec_unresolved_func_ptr(hw_addr vaddr,hw_addr len,uint32_t val,void *data);
void nostop_watchpoint_exec_denpendency(hw_addr vaddr,hw_addr len,uint32_t val,void *data);
void nostop_watchpoint_exec_overwrite_vec(hw_addr vaddr,hw_addr len,uint32_t val, void *data);

bool arm_exec_loop_bbl(hw_addr pc,uint32_t id);
void post_thread_exec(int exec_ret);
bool arm_exec_bbl(hw_addr pc,uint32_t id);
void enable_nvic_hook(int irq);
uint64_t mmio_read_common(void *opaque,hw_addr addr,unsigned size);
void mmio_write_common(void *opaque,hw_addr addr,uint64_t data,unsigned size);
void prepare_exit(uint32_t exit_code,uint32_t exit_pc = 0, uint32_t exit_lr = 0, uint32_t exit_stream_id = 0, uint32_t exit_mmio_addr = 0,uint32_t mmio_len = 0);
bool exit_with_code_start();
void terminate_simulation();
void init(int argc, char **argv);
int run_config();



extern int mode;

extern SIMULATOR_CONFIG* config;



extern uint8_t *__afl_share_fuzz_queue_data;
extern uint8_t *__afl_share_stream_data;
extern uint8_t *__afl_area_ptr;
// uint32_t __afl_prev_loc;


extern int fd_to_fuzzer, fd_from_fuzzer;

extern FILE *flog;
extern FILE *f_crash_log;
extern FILE *f_irq_log;
extern FILE *f_cov_log;

extern uint64_t nommio_executed_bbls;
extern uint64_t max_bbl_exec;


extern EXIT_INFO exit_info;
extern bool next_bbl_should_exit;


extern uint32_t run_index;

extern string dump_dir;
extern string model_dir;
extern string log_dir;
extern string fuzzware_config_filename;
extern string cov_log;


#endif

