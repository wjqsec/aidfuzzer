#ifndef SIMULATOR_INCLUDED
#define SIMULATOR_INCLUDED
bool arm_exec_loop_bbl(hwaddr pc,uint32_t id);
void nostop_watchpoint_exec_mem(hwaddr vaddr,hwaddr len,uint32_t val, void *data);
void nostop_watchpoint_exec_func(hwaddr vaddr,hwaddr len,uint32_t val,void *data);


void post_thread_exec(int exec_ret);
bool arm_exec_bbl(hwaddr pc,uint32_t id);
void enable_nvic_hook(int irq);
uint64_t mmio_read_common(void *opaque,hwaddr addr,unsigned size);
void mmio_write_common(void *opaque,hwaddr addr,uint64_t data,unsigned size);
void prepare_exit(uint32_t code,uint32_t stream_id,uint64_t pc,uint32_t num_mmio,u32 stream_dumped,uint64_t lr);
bool exit_with_code_start();
void terminate();
void nostop_watchpoint_exec_denpendency(hwaddr vaddr,hwaddr len,uint32_t val,void *data);
#endif