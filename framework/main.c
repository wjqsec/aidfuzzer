#include <stdbool.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h> 
#include <sys/types.h>
#include <sys/shm.h>
#include <unistd.h>
#include "xx.h"

#define DBG
//#define AFL

uint8_t *__afl_area_ptr;
uint32_t __afl_prev_loc;
int status = 0;
int tmp;
FILE *file;

uint64_t count = 0;
void __afl_map_shm(void) {

  char *id_str = getenv("__AFL_SHM_ID");

  if (id_str) {
    uint32_t shm_id = atoi(id_str);

    __afl_area_ptr = shmat(shm_id, NULL, 0);

    /* Whooooops. */
    
    if (__afl_area_ptr == (void *)-1) _exit(1);
    
    
    /* Write something into the bitmap so that even with low AFL_INST_RATIO,
       our parent doesn't give up on us. */

    __afl_area_ptr[0] = 1;

  }

}
uint64_t mmio_read(void *opaque,hwaddr addr_offset,unsigned size)
{
    uint64_t ret = rand();
    #ifdef DBG

    struct ARM_CPU_STATE state;
    get_arm_cpu_state(&state);
    fprintf(file,"mmio read loc:%p\n",state.regs[15]);
    #endif
    #ifdef AFL
    read(124,&ret,size);
    #endif
    return ret;
}
void mmio_write(void *opaque,hwaddr addr_offset,uint64_t data,unsigned size)
{
    #ifdef DBG
    struct ARM_CPU_STATE state;
    get_arm_cpu_state(&state);
    fprintf(file,"mmio write loc:%p\n",state.regs[15]);
    #endif
}
void arm_exec_bbl(regval pc,uint32_t id)
{
    #ifdef AFL
    __afl_area_ptr[__afl_prev_loc ^ id] ++;
    __afl_prev_loc = id >> 1;
    #endif
    // count ++;
    // if(count > 1000000 )
    // {
    //     write(123,&status,4);
    //     reset_arm_reg();
    //     read(122,&tmp,4);
    //     count = 0;
    // }
    #ifdef DBG

    fprintf(file,"bbl pc:%p  id:%d  loc:%d\n",pc,id,__afl_prev_loc ^ id);
    #endif

    
}
bool arm_cpu_do_interrupt_hook()
{
    //fprintf(file,"do interrupt\n");
    #ifdef DBG
    struct ARM_CPU_STATE state;
    get_arm_cpu_state(&state);
    fprintf(file,"interrupt bbl pc:%p  r0:%x, r1:%x, r2:%x, r3:%x, sp:%x\n",state.regs[15], state.regs[0],state.regs[1],state.regs[2],state.regs[3],state.regs[13]);
    #endif

    #ifdef AFL
    write(123,&status,4);
    reset_arm_reg();
    read(122,&tmp,4);
    #endif
    return false;
}
void post_thread_exec(int exec_ret)
{
    // for(int i = 0; i < 1 << 16 ; i ++)
    // {
    //     if(__afl_area_ptr[i] != 0)
    //     {
    //         fprintf(file,"index:%d is not zero is %d\n",i,__afl_area_ptr[i]);
    //     }
    // }
    // fprintf(file,"post thread\n");
    #ifdef DBG
    struct ARM_CPU_STATE state;
    get_arm_cpu_state(&state);
    fprintf(file,"post thread exec:%d  pc:%p\n",exec_ret,state.regs[15]);
    #endif
    //if(exec_ret == 65539)
    // {
    //     write(123,&status,4);
    //     reset_arm_reg();
    //     read(122,&tmp,4);
    // }
}
void exec_ins_icmp(uint64_t val1,uint64_t val2, int used_bits)
{
    #ifdef DBG
    fprintf(file,"ins icmp pc:arg1:%x  arg2:%x\n",val1,val2);
    #endif
}
int main(int argc, char **argv)
{
    file = fopen("/tmp/a.txt","w");
    setbuf(file,0);
    #ifdef AFL
    __afl_map_shm();
    #endif
    __afl_prev_loc = 0;
    struct Simulator *simulator;
    simulator = create_simulator(ARM,false);
    
    
    add_ram_region("firmware",0x0, 0x80000);
    // add_ram_region("on-chip-ram",0x10000000, 0x8000);
    add_ram_region("stack",0x20000000, 0x10000000);
    
    // add_mmio_region("gpio",0x2009C000, 0x4000, mmio_read, mmio_write);
    add_mmio_region("APB0",0x40000000, 0x80000, mmio_read, mmio_write);
    add_mmio_region("APB1",0x40080000, 0x80000, mmio_read, mmio_write);
    add_mmio_region("AHB",0x50000000, 0x200000, mmio_read, mmio_write);
    register_exec_bbl_hook(arm_exec_bbl);
    register_do_interrupt_hook(arm_cpu_do_interrupt_hook);
    register_post_thread_exec_hook(post_thread_exec);
    register_exec_ins_icmp_hook(exec_ins_icmp);
    init_simulator(simulator);
    load_file("./mbed-os-example-blinky.bin",0);
    reset_arm_reg();
    #ifdef AFL
    read(122,&tmp,4);
    #endif
    exec_simulator(simulator);
}
