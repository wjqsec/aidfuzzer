#ifndef SNAPSHOT_INCLUDED
#define SNAPSHOT_INCLUDED

#include "config.h"
struct SNAPSHOT_MEM_SEG
{
    uint8_t *data;
    hwaddr start;
    uint32_t len;
};
struct ARMM_SNAPSHOT
{
    int num_segs;
    struct SNAPSHOT_MEM_SEG mems[MAX_NUM_MEM_REGION];
    void *arm_ctx;
};


static struct ARMM_SNAPSHOT* arm_take_snapshot()
{
    struct ARMM_SNAPSHOT *snap = (struct ARMM_SNAPSHOT*)malloc(sizeof(struct ARMM_SNAPSHOT));
    snap->num_segs = 0;
    snap->arm_ctx = save_arm_ctx_state();

    for(int i = 0; i < MAX_NUM_MEM_REGION ; i ++)
    {
        if(config->segs[i].size && !config->segs[i].readonly && config->segs[i].type == SEG_RAM)
        {
            snap->mems[snap->num_segs].len = config->segs[i].size;
            snap->mems[snap->num_segs].start = config->segs[i].start;
            snap->mems[snap->num_segs].data = (uint8_t*)malloc(snap->mems[snap->num_segs].len);
            read_ram(snap->mems[snap->num_segs].start,snap->mems[snap->num_segs].len,snap->mems[snap->num_segs].data);
            snap->num_segs++;
        }
    }

    return snap;    
}

static void arm_restore_snapshot(struct ARMM_SNAPSHOT* snap)
{
    
    static uint8_t dirty_bits[0x1000];
    restore_arm_ctx_state(snap->arm_ctx);
    int page_size = target_pagesize();
    for(int num_seg = 0; num_seg < snap->num_segs; num_seg++)
    {
        int num_pages = snap->mems[num_seg].len / page_size;
        
        get_dirty_pages(snap->mems[num_seg].start, snap->mems[num_seg].len, (unsigned long*)dirty_bits);
        for(int i = 0 ; i < num_pages ; i++)
        {
            if(1 & (dirty_bits[i / 8] >> (i & 7)))
            {
                uint32_t offset = page_size * i;
                write_ram(snap->mems[num_seg].start + offset ,page_size, snap->mems[num_seg].data + offset);
            }
            
        }  
    }

}

static struct ARMM_SNAPSHOT *org_snap,*new_snap;


hwaddr snapshot_point = 0;
struct ARM_CPU_STATE state111;
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


bool exec_bbl_snapshot(hwaddr pc,uint32_t id)
{
    int i;
    static bool returned = false;
    bool pc_changed;
    if(snapshot_point == pc)
    {
        
        register_post_thread_exec_hook(post_thread_exec);
        register_exec_bbl_hook(arm_exec_bbl);
        register_enable_nvic_hook(enable_nvic_hook);
        for(i = 0; i < MAX_NUM_MEM_REGION ; i++)
        {
            if(config->segs[i].size == 0)
                break;
            if(config->segs[i].type != SEG_MMIO)
                continue;
            add_mmio_region(config->segs[i].name,config->segs[i].start, config->segs[i].size, mmio_read_common, mmio_write_common,(void*)config->segs[i].start);
        }
        new_snap = arm_take_snapshot();

        prepare_exit(EXIT_FORKSRV_UP,0,0,0,0);
        pc_changed = exit_with_code_start();

        return pc_changed;
    }
    else if(snapshot_point && !returned)
    {
       
        arm_restore_snapshot(org_snap);
        returned = true;
        return true;
    }
    simple_log(flog,false,"snapshot bbl",0,0,0);

    __afl_area_ptr[id] ++;
    return false;
}
#endif