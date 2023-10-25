#ifndef SIMULATOR_INCLUDED
#define SIMULATOR_INCLUDED
#include <stdio.h>
#include "xx.h"
#include "fuzzer.h"
#include "config.h"

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
void prepare_exit(uint32_t code,uint32_t stream_id,uint64_t pc,u32 stream_dumped,uint64_t lr,u32 mmio_len);
bool exit_with_code_start();
void terminate();
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


extern uint64_t nommio_executed_bbls;
extern uint64_t max_bbl_exec;


extern EXIT_INFO exit_info;
extern bool next_bbl_should_exit;


extern uint32_t run_index;

extern char *dump_dir;
extern char *model_dir;
extern char *log_dir;
extern char *fuzzware_config_filename;

extern bool model_systick;

#endif

