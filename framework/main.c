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
//#define CRASH_DBG
#define AFL

#define FORKSRV_CTLFD          198
#define FORKSRV_DATAFD          200

#define EXIT_NONE 0
#define EXIT_TIMEOUT 1
#define EXIT_OUTOFSEED 2
#define EXIT_CRASH 3


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

bool should_exit = false;
uint32_t exit_code = 0;

void __afl_map_shm(void) {

  char *id_str = getenv("__AFL_SHM_ID");
  if (id_str) {
    uint32_t shm_id = atoi(id_str);
    __afl_area_ptr = shmat(shm_id, NULL, 0);
    if (__afl_area_ptr == (void *)-1) _exit(1);
  }

}

#define NUM_MEM_SNAPSHOT 5
struct MEM_SEG
{
    uint8_t *data;
    hwaddr start;
    uint32_t len;
} mems[NUM_MEM_SNAPSHOT];
void *arm_ctx;
void take_snapshot()
{
    arm_ctx = save_arm_ctx_state();

    mems[0].len = 0x80000;
    mems[0].start = 0;
    mems[0].data = (uint8_t*)malloc(mems[0].len);
    read_ram(mems[0].start,mems[0].len,mems[0].data);

    mems[1].len = 0x8000;
    mems[1].start = 0x10000000;
    mems[1].data = (uint8_t*)malloc(mems[1].len);
    read_ram(mems[1].start,mems[1].len,mems[1].data);

    mems[2].len = 0x20000;
    mems[2].start = 0x20000000;
    mems[2].data = (uint8_t*)malloc(mems[2].len);
    read_ram(mems[2].start,mems[2].len,mems[2].data);

    mems[3].len = 0x30000;
    mems[3].start = 0x20060000;
    mems[3].data = (uint8_t*)malloc(mems[3].len);
    read_ram(mems[3].start,mems[3].len,mems[3].data);

    mems[4].len = 0;
}
void restore_snapshot()
{
    static uint8_t dirty_bits[0x1000];
    restore_arm_ctx_state(arm_ctx);
    int page_size = target_pagesize();
    for(int num_mem = 0; num_mem < NUM_MEM_SNAPSHOT; num_mem++)
    {
        if(mems[num_mem].len ==0)
            continue;
        int num_pages_byte = mems[5].len / page_size;
        
        get_dirty_pages(mems[num_mem].start, mems[num_mem].len, dirty_bits);
        for(int i = 0 ; i < num_pages_byte ; i++)
        {
            for(int j = 0 ; j < 8 ; j++)
            {
                if(dirty_bits[i] & (1 << j))
                {
                    uint32_t offset = page_size * (i * 8 + j);
                    fprintf(file,"restore %x  %x",offset,mems[num_mem].data);
                    write_ram(mems[num_mem].start + offset ,page_size, mems[num_mem].data + offset);
                }
            }
        }
    }
    for(int num_mem = 0; num_mem < NUM_MEM_SNAPSHOT; num_mem++)
    {
        if(mems[num_mem].len ==0)
            continue;
        clear_dirty_mem(mems[num_mem].start, mems[num_mem].len);
    }
    
}

void exit_with_code_start_new(int32_t code)
{
    int32_t tmp = code;
    #ifdef DBG
    fprintf(file,"exit_code = %x\n",tmp);
    #endif

    
    write(FORKSRV_CTLFD+1 , &tmp,4);

    restore_snapshot();
    execed_bbl_count = 0;
    __afl_prev_loc = 0;
    read(FORKSRV_CTLFD,&tmp,4);

    
    

}
uint64_t mmio_read(void *opaque,hwaddr addr_offset,unsigned size)
{
    uint64_t ret = 0;
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
        should_exit = true;
        exit_code = EXIT_OUTOFSEED;
        return ret;
    }
    read(FORKSRV_DATAFD,&bbl_id_recv,4);
    read(FORKSRV_DATAFD,&ret,len_send);
    #endif

    #ifdef DBG
    struct ARM_CPU_STATE state;
    get_arm_cpu_state(&state);
    fprintf(file,"mmio read loc:%p val:%x\n",state.regs[15],ret);
    #endif
    return ret;
}
void mmio_write(void *opaque,hwaddr addr_offset,uint64_t data,unsigned size)
{
    // #ifdef DBG
    // struct ARM_CPU_STATE state;
    // get_arm_cpu_state(&state);
    // fprintf(file,"mmio write loc:%p\n",state.regs[15]);
    // #endif
}
bool arm_exec_bbl(regval pc,uint32_t id)
{
    #ifdef DBG

    fprintf(file,"bbl pc:%p\n",pc);
    #endif

    // static bool first = true;
    // if(first)
    // {
    //     take_snapshot();
    //     first = false;
    // }
    // execed_bbl_count++;
    // if(execed_bbl_count > 50)
    // {
    //     fprintf(file,"restore point\n");
    //     //restore_snapshot();
    //     struct ARM_CPU_STATE state;
    //     get_arm_cpu_state(&state);
    //     state.regs[15] = 0x388;
    //     set_arm_cpu_state(&state);
    //     execed_bbl_count = 0;
    //     return true;
    // }
    // return false;
    // else 
    // {
    //     struct ARM_CPU_STATE state;
    //     get_arm_cpu_state(&state);
    //     fprintf(file,"non restore pc:%x\n",state.regs[15]);
    // }
    
    
    #ifdef AFL
    __afl_area_ptr[__afl_prev_loc ^ id] ++;
    __afl_prev_loc = id >> 1;
    execed_bbl_count++;
    cur_bbl_id = pc;
    if(execed_bbl_count > 1000)
    {
        exit_with_code_start_new(EXIT_TIMEOUT);
        return true;
    }
    if(should_exit)
    {
        exit_with_code_start_new(exit_code);
        should_exit = false;
        return true;
    }
    #endif
    return false;
    

    
}
bool arm_cpu_do_interrupt_hook(int32_t exec_index)
{  
    #ifdef CRASH_DBG
    struct ARM_CPU_STATE state;
    get_arm_cpu_state(&state);
    uint32_t sp0, sp1,sp2;
    read_ram(state.regs[13],4, &sp0);
    read_ram(state.regs[13] + 4,4, &sp1);
    read_ram(state.regs[13] + 8,4, &sp2);
    fprintf(file,"%d interrupt bbl index:%d pc:%p  r0:%x, r1:%x, r2:%x, r3:%x, sp:%x [sp]=%x, [sp+4]=%x [sp+8]=%x\n",iii,exec_index, state.regs[15], state.regs[0],state.regs[1],state.regs[2],state.regs[3],state.regs[13], sp0, sp1,sp2);
    #endif


    if(exec_index == EXCP_SWI || 
       exec_index == EXCP_EXCEPTION_EXIT)
       {
        return true;
       }
        
   

    #ifdef AFL
    exit_with_code_start_new(EXIT_CRASH);
    #endif
    
    return false;
}
void post_thread_exec(int exec_ret)
{

    #ifdef AFL
    exit_with_code_start_new(EXIT_NONE);
    #endif
    #ifdef DBG
    struct ARM_CPU_STATE state;
    get_arm_cpu_state(&state);
    fprintf(file,"post thread exec:%d  pc:%p\n",exec_ret,state.regs[15]);
    #endif

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
    add_ram_region("on-chip-ram",0x10000000, 0x8000);
    add_ram_region("on-chip-ram2",0x20000000, 0x20000);
    add_ram_region("stack",0x20060000, 0x30000);
    
    add_mmio_region("gpio",0x2009C000, 0x4000, mmio_read, mmio_write);
    add_mmio_region("APB0",0x40000000, 0x80000, mmio_read, mmio_write);
    add_mmio_region("APB1",0x40080000, 0x80000, mmio_read, mmio_write);
    add_mmio_region("AHB",0x50000000, 0x200000, mmio_read, mmio_write);
    register_exec_bbl_hook(arm_exec_bbl);
    register_arm_do_interrupt_hook(arm_cpu_do_interrupt_hook);
    register_post_thread_exec_hook(post_thread_exec);
    //register_exec_ins_icmp_hook(exec_ins_icmp);
    init_simulator(simulator);
    load_file("/root/fuzzer/xxfuzzer/framework/mbed-os-example-blinky.bin",0);
    reset_arm_reg();
    take_snapshot();
    #ifdef AFL
    
    write(FORKSRV_CTLFD+1 , &tmp,4);
    read(FORKSRV_CTLFD,&tmp,4);
    #endif
    exec_simulator(simulator);
}
