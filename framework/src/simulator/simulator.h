#ifndef SIMULATOR_INCLUDED
#define SIMULATOR_INCLUDED

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
void prepare_exit(uint32_t code,uint32_t stream_id,uint64_t pc,uint32_t num_mmio,u32 stream_dumped,uint64_t lr);
bool exit_with_code_start();
void terminate();

#endif