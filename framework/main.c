#include <stdbool.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h> 
#include <sys/types.h>
#include <sys/shm.h>
#include <unistd.h>

#include <string.h>
#include "xx.h"

//#define DBG
#define AFL

#define FORKSRV_CTLFD          198
#define FORKSRV_DATAFD          200

#define EXIT_NONE 0
#define EXIT_TIMEOUT 1
#define EXIT_CRASH 2


struct __attribute__((__packed__)) Data_protocol
{
  #define FUZZ_REQ 0x1
  #define CMP_VAL 0x2
  #define FUZZ_OUTPUT 0x3
  #define ACK 0x4
  uint8_t type;
  int32_t len; // -1 means no more data
  uint32_t bbl_id;
  uint8_t data[];
};

uint8_t *__afl_area_ptr;
uint32_t __afl_prev_loc;


FILE *file;

uint64_t execed_bbl_count = 0;
uint32_t cur_bbl_id;

void __afl_map_shm(void) {

  char *id_str = getenv("__AFL_SHM_ID");
  if (id_str) {
    uint32_t shm_id = atoi(id_str);
    __afl_area_ptr = shmat(shm_id, NULL, 0);
    if (__afl_area_ptr == (void *)-1) _exit(1);
  }

}

uint64_t mmio_read(void *opaque,hwaddr addr_offset,unsigned size)
{
    uint64_t ret = 0;

    #ifdef DBG
    struct ARM_CPU_STATE state;
    get_arm_cpu_state(&state);
    fprintf(file,"mmio read loc:%p\n",state.regs[15]);
    #endif

    #ifdef AFL
    static uint8_t buf[32];
    uint8_t  type_recv;
    int32_t len_recv;
    uint32_t bbl_id_recv;

    uint8_t  type_send;
    int32_t len_send;
    uint32_t bbl_id_send;
    
    buf[0] = FUZZ_REQ;
    len_send = size;
    memcpy(buf+1, &len_send, 4);
    memcpy(buf+5, &cur_bbl_id,4);
    write(FORKSRV_DATAFD+1 , buf, 9);

    read(FORKSRV_DATAFD,&type_recv,1);
    if(type_recv != FUZZ_OUTPUT)
    {
        printf("error type_recv\n");
        exit(0);
    }
    read(FORKSRV_DATAFD,&len_recv,4);
    if(len_recv == -1)
    {
        int32_t exit_code = EXIT_TIMEOUT;
        write(FORKSRV_CTLFD+1 , &exit_code,4);
        reset_arm_reg();
        execed_bbl_count = 0;
    }
    read(FORKSRV_DATAFD,&bbl_id_recv,4);
    read(FORKSRV_DATAFD,&ret,len_send);
    printf("read end\n");
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
    execed_bbl_count++;
    cur_bbl_id = pc;
    if(execed_bbl_count > 10000)
    {
        int32_t exit_code = EXIT_TIMEOUT;
        write(FORKSRV_CTLFD+1 , &exit_code,4);
        reset_arm_reg();
        execed_bbl_count = 0;
    }
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
    int32_t exit_code = EXIT_CRASH;
    write(FORKSRV_CTLFD+1 , &exit_code,4);
    reset_arm_reg();
    execed_bbl_count = 0;
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
    #ifdef AFL
    int32_t exit_code = EXIT_NONE;
    write(FORKSRV_CTLFD+1 , &exit_code,4);
    reset_arm_reg();
    execed_bbl_count = 0;
    #endif
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
void exec_ins_icmp(regval pc,uint64_t val1,uint64_t val2, int used_bits, int immediate_index)
{
    #ifdef DBG
    fprintf(file,"ins icmp pc:%p\n",pc);
    #endif
}
int main(int argc, char **argv)
{
    uint32_t tmp; 
    file = fopen("/tmp/a.txt","w");
    setbuf(file,0);
    #ifdef AFL
    __afl_map_shm();
    __afl_prev_loc = 0;
    #endif
    
    struct Simulator *simulator;
    simulator = create_simulator(ARM,false);
    
    
    add_ram_region("firmware",0x0, 0x80000);
    // add_ram_region("on-chip-ram",0x10000000, 0x8000);
    add_ram_region("stack",0x20000000, 0x10000000);
    
    add_mmio_region("gpio",0x2009C000, 0x4000, mmio_read, mmio_write);
    add_mmio_region("APB0",0x40000000, 0x80000, mmio_read, mmio_write);
    add_mmio_region("APB1",0x40080000, 0x80000, mmio_read, mmio_write);
    add_mmio_region("AHB",0x50000000, 0x200000, mmio_read, mmio_write);
    register_exec_bbl_hook(arm_exec_bbl);
    register_do_interrupt_hook(arm_cpu_do_interrupt_hook);
    register_post_thread_exec_hook(post_thread_exec);
    //register_exec_ins_icmp_hook(exec_ins_icmp);
    init_simulator(simulator);
    load_file("/root/fuzzer/xxfuzzer/framework/mbed-os-example-blinky.bin",0);
    reset_arm_reg();
    
    #ifdef AFL
    write(FORKSRV_CTLFD+1 , &tmp,4);
    read(FORKSRV_CTLFD,&tmp,4);
    #endif
    exec_simulator(simulator);
}
