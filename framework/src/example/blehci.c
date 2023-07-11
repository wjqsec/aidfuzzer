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
#include "xx.h"

FILE *f_log;
uint64_t mmio_read(void *opaque,hwaddr addr,unsigned size)
{
    printf("mmio\n");
    return 0;
    
}
void mmio_write(void *opaque,hwaddr addr,uint64_t data,unsigned size)
{

}

bool exec_bbl(regval pc,uint32_t id,int64_t bbl)
{
    fprintf(f_log,"pc %x bbl:%d\n",pc,bbl);
    return false;
}
bool arm_cpu_do_interrupt_hook(int32_t exec_index)
{
    // struct ARM_CPU_STATE state;
    // get_arm_cpu_state(&state);
    // uint32_t sp0, sp1,sp2;
    // read_ram(state.regs[13],4, &sp0);
    // read_ram(state.regs[13] + 4,4, &sp1);
    // read_ram(state.regs[13] + 8,4, &sp2);
    // printf("crash index:%d pc:%p  r0:%x, r1:%x, r2:%x, r3:%x, r4:%x r5:%x r6:%x r7:%x r8:%x r9:%x r10:%x r11:%x ip:%x sp:%x lr:%x sp:%x [sp]=%x, [sp+4]=%x [sp+8]=%x\n",
    // exec_index,state.regs[15], state.regs[0],state.regs[1],state.regs[2],state.regs[3],state.regs[4],state.regs[5],state.regs[6],state.regs[7],state.regs[8],state.regs[9],
    // state.regs[10],state.regs[11],state.regs[12],state.regs[13],state.regs[14], sp0, sp1,sp2);
    return  true;
}
void post_thread_exec(int exec_ret)
{
    struct ARM_CPU_STATE state;
    get_arm_cpu_state(&state);
    printf("post thread exec:%d  pc:%p\n", exec_ret,state.regs[15]);
}
int main()
{
    struct stat f_stat;
    char *buf;
    FILE *f_binary;
    struct ARM_CPU_STATE state;
    struct Simulator *simulator;
    simulator = create_simulator(ARM,false);
    set_armv7_vecbase(0xc020);
    init_simulator(simulator);
    stat("./blehci.bin",&f_stat);
    f_binary = fopen("./blehci.bin","rb");
    f_log = fopen("./log.txt","w");
    buf = (char *)malloc(f_stat.st_size);
    fread(buf,f_stat.st_size,1,f_binary);
    add_ram_region("dynamically_added_crash_region_00000000",0, 0xa000,false);
    add_ram_region("dynamically_added_crash_region_10000130",0xfffb000, 0xa000,false);
    add_ram_region("ram",0x20000000, 0x100000,false);
    add_ram_region("exe",0xc000, 0x1d000,false);
    add_mmio_region("mmio",0x40000000, 0x20000000, mmio_read, mmio_write,(void*)0x40000000);
    write_ram(0xc020,f_stat.st_size,buf);
    register_exec_bbl_hook(exec_bbl);
    register_arm_do_interrupt_hook(arm_cpu_do_interrupt_hook);
    register_post_thread_exec_hook(post_thread_exec);
    reset_arm_reg();
    get_arm_cpu_state(&state);
    printf("pc :%x\n",state.regs[15]);
    exit(0);
}