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
#include <glib.h>
#include <string.h>
#include "xx.h"
#define likely(_x)   __builtin_expect(!!(_x), 1)
#define unlikely(_x)  __builtin_expect(!!(_x), 0)

//#define DBG
#define CRASH_DBG
//#define TRACE_DBG
#define AFL

#define FORKSRV_CTLFD          198
#define FORKSRV_DATAFD          200

#define EXIT_NONE 0
#define EXIT_TIMEOUT 1
#define EXIT_OUTOFSEED 2
#define EXIT_CRASH 3



#define FUZZ_REQ 0x1
#define CMP_VAL 0x2
#define FUZZ_OUTPUT 0x3
#define ACK 0x4


uint8_t *__afl_area_ptr;
uint32_t __afl_prev_loc;

int irq_level = 0;

FILE *flog;

uint64_t execed_bbl_count = 0;
uint32_t max_bbl_exec = 100000;



bool should_exit = false;
uint32_t exit_code = 0;
uint32_t exit_info;
uint64_t exit_pc;

GArray* bbl_records;

uint32_t run_index;
void __afl_map_shm(void) {

  char *id_str = getenv("__AFL_SHM_ID");
  if (id_str) {
    uint32_t shm_id = atoi(id_str);
    __afl_area_ptr = shmat(shm_id, NULL, 0);
    if (__afl_area_ptr == (void *)-1) _exit(1);
  }

}

struct SNAPSHOT_MEM_SEG
{
    uint8_t *data;
    hwaddr start;
    uint32_t len;
};
struct ARMM_SNAPSHOT
{
    #define NUM_MEM_SNAPSHOT 5
    struct SNAPSHOT_MEM_SEG mems[NUM_MEM_SNAPSHOT];
    void *arm_ctx;
};

struct ARMM_SNAPSHOT *org_snap, *new_snap;
struct ARMM_SNAPSHOT* arm_take_snapshot()
{
    struct ARMM_SNAPSHOT *snap = (struct ARMM_SNAPSHOT*)malloc(sizeof(struct ARMM_SNAPSHOT));
    snap->arm_ctx = save_arm_ctx_state();
    snap->mems[0].len = 0;
    snap->mems[1].len = 0;
    snap->mems[2].len = 0;
    snap->mems[3].len = 0;
    snap->mems[4].len = 0;

    int index = 0;
    snap->mems[index].len = 0x1000;
    snap->mems[index].start = 0;
    snap->mems[index].data = (uint8_t*)malloc(snap->mems[index].len);
    read_ram(snap->mems[index].start,snap->mems[index].len,snap->mems[index].data);
    index++;

    snap->mems[index].len = 0x20000;
    snap->mems[index].start = 0x20000000;
    snap->mems[index].data = (uint8_t*)malloc(snap->mems[index].len);
    read_ram(snap->mems[index].start,snap->mems[index].len,snap->mems[index].data);
    index++;

    // snap->mems[index].len = 0x10000;
    // snap->mems[index].start = 0x1e0000;
    // snap->mems[index].data = (uint8_t*)malloc(snap->mems[index].len);
    // read_ram(snap->mems[index].start,snap->mems[index].len,snap->mems[index].data);
    // index++;

    return snap;    
}

void arm_restore_snapshot(struct ARMM_SNAPSHOT* snap)
{
    static uint8_t dirty_bits[0x1000];
    restore_arm_ctx_state(snap->arm_ctx);
    int page_size = target_pagesize();
    for(int num_mem = 0; num_mem < NUM_MEM_SNAPSHOT; num_mem++)
    {
        if(snap->mems[num_mem].len ==0)
            continue;
        int num_pages = snap->mems[num_mem].len / page_size;
        
        // write_ram(snap->mems[num_mem].start,snap->mems[num_mem].len,snap->mems[num_mem].data);
        
        get_dirty_pages(snap->mems[num_mem].start, snap->mems[num_mem].len, (unsigned long*)dirty_bits);
        for(int i = 0 ; i < num_pages ; i++)
        {
            if(1 & (dirty_bits[i / 8] >> (i & 7)))
            {
                uint32_t offset = page_size * i;
                //fprintf(flog,"restore memory %x\n",snap->mems[num_mem].start + offset);
                write_ram(snap->mems[num_mem].start + offset ,page_size, snap->mems[num_mem].data + offset);
            }
            
        }  
    }
    for(int num_mem = 0; num_mem < NUM_MEM_SNAPSHOT; num_mem++)
    {
        if(snap->mems[num_mem].len ==0)
            continue;
        clear_dirty_mem(snap->mems[num_mem].start, snap->mems[num_mem].len);
    }
}


void exit_with_code_start_new(int32_t code)
{

    int32_t tmp = code;
    uint32_t record;

    #ifdef DBG
    fprintf(flog,"%d->exit_code = %x pc = %x\n",run_index, tmp,exit_pc);
    run_index++;
    #endif

    #ifdef CRASH_DBG
    if(tmp == EXIT_CRASH)
    {
        struct ARM_CPU_STATE state;
        get_arm_cpu_state(&state);
        uint32_t sp0, sp1,sp2;
        read_ram(state.regs[13],4, &sp0);
        read_ram(state.regs[13] + 4,4, &sp1);
        read_ram(state.regs[13] + 8,4, &sp2);
        fprintf(flog,"crash pc:%p  r0:%x, r1:%x, r2:%x, r3:%x, r4:%x r5:%x r6:%x r7:%x r8:%x r9:%x r10:%x r11:%x ip:%x sp:%x lr:%x sp:%x [sp]=%x, [sp+4]=%x [sp+8]=%x\n",
        state.regs[15], state.regs[0],state.regs[1],state.regs[2],state.regs[3],state.regs[4],state.regs[5],state.regs[6],state.regs[7],state.regs[8],state.regs[9],
        state.regs[10],state.regs[11],state.regs[12],state.regs[13],state.regs[14], sp0, sp1,sp2);
    }
    #endif


    write(FORKSRV_CTLFD+1 , &tmp,4);
    write(FORKSRV_CTLFD+1 , &exit_info,4);
    write(FORKSRV_CTLFD+1 , &exit_pc,4);        
    arm_restore_snapshot(new_snap);
    execed_bbl_count = 0;
    exit_info = 0;
    // __afl_prev_loc = 0;
    // irq_level = 0;
    //read(FORKSRV_CTLFD,&record,4);

    #ifdef TRACE_DBG
    if(record)
    {
        fprintf(flog,"trace:\n");
        for (int i = 0; i < bbl_records->len; i++) 
        {
           fprintf(flog,"%-8x\n",g_array_index(bbl_records, hwaddr, i));
        }
        fprintf(flog,"end\n");
        g_array_set_size(bbl_records, 0);
    }
    #endif

    read(FORKSRV_CTLFD,&tmp,4);  // start new run
    
    
}

uint64_t mmio_read_common(void *opaque,hwaddr addr,unsigned size)
{
    addr = (hwaddr)opaque + addr;
    uint64_t ret = 0;
    #ifdef AFL

    static uint8_t buf[32];
    uint8_t  type_recv;
    int32_t len;
    uint32_t mmio_id_send = addr & 0xfffffff0;
    
    buf[0] = FUZZ_REQ;
    len = size;
    memcpy(buf+1, &len, 4);
    memcpy(buf+5, &mmio_id_send,4);
    write(FORKSRV_DATAFD+1 , buf, 9);
    read(FORKSRV_DATAFD,&len,4);
    if(len == -1)
    {
        
        should_exit = true;
        exit_code = EXIT_OUTOFSEED;
        exit_info = mmio_id_send;
        return ret;
    }
    read(FORKSRV_DATAFD,&ret,len);
    #endif

    #ifdef DBG
    struct ARM_CPU_STATE state;
    get_arm_cpu_state(&state);
    fprintf(flog,"%d->mmio read pc:%p offset:%x val:%x\n",run_index, state.regs[15],addr,ret);
    #endif

    return ret;
}

void mmio_write_common(void *opaque,hwaddr addr,uint64_t data,unsigned size)
{
    addr = (hwaddr)opaque + addr;
    #ifdef DBG
    struct ARM_CPU_STATE state;
    get_arm_cpu_state(&state);
    fprintf(flog,"%d->mmio write pc:%p offset:%x val:%x\n",run_index, state.regs[15],addr,data);
    #endif
}


bool arm_exec_bbl(regval pc,uint32_t id)
{
    #ifdef AFL
    
    if(unlikely(execed_bbl_count >= max_bbl_exec))
    {
        exit_with_code_start_new(EXIT_TIMEOUT);
        return true;
    }
    if(unlikely(should_exit))  //run out of seed
    {
        exit_with_code_start_new(exit_code);
        should_exit = false;
        return true;
    }
    #endif

    

    // if(unlikely(pc == 0x8002FC2))  //fail function reached
    // {
        
    //     GArray* irqs = get_enabled_nvic_irq();
    //     printf("irqs:");
    //     for (int i = 0; i < irqs->len; i++) 
    //     {
    //        printf("%-8d ",g_array_index(irqs, int, i));
    //     }
    //     printf("\n");
    //     return true;
    // }
    


    #ifdef DBG
    fprintf(flog,"%d->bbl pc:%p\n",run_index, pc);

    // static printed =false;
    // uint32_t tt1 = 55;
    // uint32_t tt2 = 0;
    // uint32_t tt3 = 0;
    // uint32_t tt4 = 0;
    // uint32_t tt5 = 0;
    // if(pc == 0x0800CE18)
    // {
    //     read_ram(0x80133a0,4, &tt1);
    //     read_ram(0x80133a0 + 4,4, &tt2);
    //     read_ram(0x80133a0 + 8,4, &tt3);
    //     read_ram(0x80133a0 + 0xc,4, &tt4);
    //     read_ram(0x80133a0 + 0x10,4, &tt5);
    //     printf("%x  %x  %x  %x  %x\n",tt1,tt2,tt3,tt4,tt5);

    // }
    
    
    // if(pc == 0x8000598)
    // {
    //     struct ARM_CPU_STATE state;
    //     get_arm_cpu_state(&state);
    //     uint32_t sp0, sp1,sp2;
    //     uint32_t mem1, mem2,mem3;
    //     read_ram(state.regs[13],4, &sp0);
    //     read_ram(state.regs[13] + 4,4, &sp1);
    //     read_ram(state.regs[13] + 8,4, &sp2);
    //     read_ram(0x200010A0,4, &mem1);
    //     read_ram(state.regs[0] + 4,4, &mem2);
    //     fprintf(flog,"%d->what pc:%p  r0:%x, r1:%x, r2:%x, r3:%x, r4:%x r5:%x r6:%x r7:%x r8:%x r9:%x sp:%x [sp]=%x, [sp+4]=%x [sp+8]=%x [mem1]=%x [mem2]=%x\n",run_index,
    //             state.regs[15], state.regs[0],state.regs[1],state.regs[2],state.regs[3],state.regs[4],state.regs[5],state.regs[6],state.regs[7],state.regs[8],state.regs[9],state.regs[13], sp0, sp1,sp2,
    //             mem1,mem2
    //             );
 
    // }
    #endif
    
    #ifdef AFL

    __afl_area_ptr[id] ++;
    exit_pc = pc;
    execed_bbl_count++;

    // if((execed_bbl_count & 0x1ff) == 0)
    // {
    //     GArray* irqs = get_enabled_nvic_irq();
    //     int irq = g_array_index(irqs, int, rand() % irqs->len);
    //         insert_nvic_intc(irq,false);
    //     // if(irq != 15 && irq != 53&& irq != 44 && irq != 36 && irq != 35)  
    //     //     printf("irq:%d\n",irq);
    //     g_array_free(irqs,false);
    //     return false;
    // }

    #endif

    #ifdef TRACE_DBG
    g_array_append_val(bbl_records, pc);
    #endif 
    return false;
    

    
}
bool arm_cpu_do_interrupt_hook(int32_t exec_index)
{  
    /*
    if(exec_index == EXCP_IRQ)
    {
        // __afl_intc_old_prev_loc = __afl_prev_loc;
        // __afl_prev_loc = 0;
        irq_level++;
        return true;
    }
    if(exec_index == EXCP_EXCEPTION_EXIT)
    {
        // __afl_prev_loc = __afl_intc_old_prev_loc;
        // skip_this_bbl = true;
        irq_level--;
        return true;
    }
    */
    if(exec_index == EXCP_SWI || exec_index == EXCP_IRQ || exec_index == EXCP_EXCEPTION_EXIT)
    {
        return true;
    }

    #ifdef AFL
    // struct ARM_CPU_STATE tmp_state;
    // get_arm_cpu_state(&tmp_state);
    // exit_pc = tmp_state.regs[15];
    exit_with_code_start_new(EXIT_CRASH);
    return false;
    #endif
    
    return true;
}
void post_thread_exec(int exec_ret)
{
    insert_nvic_intc(ARMV7M_EXCP_SYSTICK, false);

    #ifdef DBG
    struct ARM_CPU_STATE state;
    get_arm_cpu_state(&state);
    fprintf(flog,"%d->post thread exec:%d  pc:%p\n",run_t ime, exec_ret,state.regs[15]);
    #endif
}
void exec_ins_icmp(regval pc,uint64_t val1,uint64_t val2, int used_bits, int immediate_index)
{
    #ifdef DBG
    fprintf(flog,"%d->ins icmp pc:%p\n",run_index, pc);
    #endif
}

/*
int run_example(int argc, char **argv)
{
    uint32_t tmp; 
    flog = fopen("/tmp/a.txt","w");
    setbuf(flog,0);
    #ifdef AFL
    __afl_map_shm();
    __afl_prev_loc = 0;
    #endif
    
    struct Simulator *simulator;
    simulator = create_simulator(ARM,false);
    
    
    add_ram_region("firmware",0x0, 0x80000,false);
    add_ram_region("on-chip-ram",0x10000000, 0x8000,false);
    add_ram_region("on-chip-ram2",0x20000000, 0x20000,false);
    add_ram_region("stack",0x20070000, 0x20000,false);
    
    add_mmio_region("gpio",0x2009C000, 0x4000, mmio_read_common, mmio_write_common);
    add_mmio_region("APB0",0x40000000, 0x80000, mmio_read_common, mmio_write_common);
    add_mmio_region("APB1",0x40080000, 0x80000, mmio_read_common, mmio_write_common);
    add_mmio_region("AHB",0x50000000, 0x200000, mmio_read_common, mmio_write_common);
    register_exec_bbl_hook(arm_exec_bbl);
    register_arm_do_interrupt_hook(arm_cpu_do_interrupt_hook);
    register_post_thread_exec_hook(post_thread_exec);
    //register_exec_ins_icmp_hook(exec_ins_icmp);
    init_simulator(simulator);
    load_file_ram("/root/fuzzer/xxfuzzer/framework/mbed-os-example-blinky.bin",0, 0,0x80000);
    reset_arm_reg();
    arm_take_snapshot();

    #ifdef AFL
    write(FORKSRV_CTLFD+1 , &tmp,4);
    read(FORKSRV_CTLFD,&tmp,4);
    #endif

    exec_simulator(simulator);
}
*/

hwaddr snapshot_point = 0;
uint64_t mmio_read_snapshot(void *opaque,hwaddr addr,unsigned size)
{
    static bool found = false;
    if(!found)
    {
        struct ARM_CPU_STATE state;
        get_arm_cpu_state(&state);
        snapshot_point = state.regs[15];
        found = true;
    }
    return 0;
    
}
void mmio_write_snapshot(void *opaque,hwaddr addr,uint64_t data,unsigned size){}

bool exec_bbl_snapshot(regval pc,uint32_t id)
{
    static bool returned = false;
    if(snapshot_point == pc)
    {
        register_arm_do_interrupt_hook(arm_cpu_do_interrupt_hook);
        register_post_thread_exec_hook(post_thread_exec);
        register_exec_bbl_hook(arm_exec_bbl);
        add_mmio_region("mmio234",0x40000000, 0x20000000, mmio_read_common, mmio_write_common,(void*)0x40000000);
        add_mmio_region("mmio345",0x1e0000, 0x10000,mmio_read_common,mmio_write_common,(void*)0x1e0000);
       
        new_snap = arm_take_snapshot();
        #ifdef AFL
        uint32_t tmp; 
        write(FORKSRV_CTLFD+1 , &tmp,4);
        read(FORKSRV_CTLFD,&tmp,4);
        #endif
        return false;
    }
    else if(snapshot_point && !returned)
    {
        arm_restore_snapshot(org_snap);
        returned = true;
        return true;
    }
    return false;
}



int run_3dprinter(int argc, char **argv)
{
    struct Simulator *simulator;
    simulator = create_simulator(ARM,false);

    set_armv7_vecbase(0x8000000);
    init_simulator(simulator);

    add_ram_region("zero",0, 0x1000,false);
    add_ram_region("ram",0x20000000, 0x20000,false);
    add_rom_region("rom",0x8000000,0x14000);
    add_ram_region("text",0x8014000, 0x3000,false);  
    
    load_file_rom("/home/w/hd/iofuzzer/xxfuzzer/framework/uEmu.3Dprinter.bin",0x8000000,0,0x14000);
    load_file_ram("/home/w/hd/iofuzzer/xxfuzzer/framework/uEmu.3Dprinter.bin",0x8014000,0x14000,0x3000);

    uint8_t *buf = (uint8_t *)malloc(0x1000);
    memset(buf,0,0x1000);
    write_ram(0,0x1000,buf);
    free(buf);

    reset_arm_reg();
    
    
    register_exec_bbl_hook(exec_bbl_snapshot);
    add_mmio_region("mmio",0x40000000, 0x20000000, mmio_read_snapshot, mmio_write_snapshot,(void*)0x40000000);
    add_mmio_region("mmio2",0x1e0000, 0x10000,mmio_read_snapshot,mmio_write_snapshot,(void*)0x1e0000);

    org_snap = arm_take_snapshot();
    exec_simulator(simulator);
}

int main(int argc, char **argv)
{
    flog = fopen("/tmp/a.txt","w");
    setbuf(flog,0);
    srand(time(NULL));
    #ifdef AFL
    __afl_map_shm();
    __afl_prev_loc = 0;
    #endif

    #ifdef TRACE_DBG
    bbl_records = g_array_new(FALSE, FALSE, sizeof(hwaddr));
    #endif

    run_3dprinter(argc,argv);
}
