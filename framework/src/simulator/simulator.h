#ifndef SIMULATOR_INCLUDED
#define SIMULATOR_INCLUDED
bool arm_exec_loop_bbl(hwaddr pc,uint32_t id);
void nostop_watchpoint_exec_mem(hwaddr vaddr,hwaddr len,uint32_t val, void *data);
void nostop_watchpoint_exec_func(hwaddr vaddr,hwaddr len,uint32_t val,void *data);
#endif