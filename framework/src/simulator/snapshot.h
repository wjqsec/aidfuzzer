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
    struct SNAPSHOT_MEM_SEG mems[MAX_NUM_MEM_REGION];
    void *arm_ctx;
};


static struct ARMM_SNAPSHOT* arm_take_snapshot()
{
    struct ARMM_SNAPSHOT *snap = (struct ARMM_SNAPSHOT*)malloc(sizeof(struct ARMM_SNAPSHOT));
    snap->arm_ctx = save_arm_ctx_state();

    for(int i = 0; i < MAX_NUM_MEM_REGION ; i ++)
    {
        snap->mems[i].len = 0;
        if(config->rams[i].size && !config->rams[i].readonly)
        {
            snap->mems[i].len = config->rams[i].size;
            snap->mems[i].start = config->rams[i].start;
            snap->mems[i].data = (uint8_t*)malloc(snap->mems[i].len);
            read_ram(snap->mems[i].start,snap->mems[i].len,snap->mems[i].data);
        }
    }

    return snap;    
}

static void arm_restore_snapshot(struct ARMM_SNAPSHOT* snap)
{
    
    static uint8_t dirty_bits[0x1000];
    restore_arm_ctx_state(snap->arm_ctx);
    int page_size = target_pagesize();
    for(int num_mem = 0; num_mem < MAX_NUM_MEM_REGION; num_mem++)
    {
        if(snap->mems[num_mem].len ==0)
            break;
        int num_pages = snap->mems[num_mem].len / page_size;
        
        get_dirty_pages(snap->mems[num_mem].start, snap->mems[num_mem].len, (unsigned long*)dirty_bits);
        for(int i = 0 ; i < num_pages ; i++)
        {
            if(1 & (dirty_bits[i / 8] >> (i & 7)))
            {
                uint32_t offset = page_size * i;
                write_ram(snap->mems[num_mem].start + offset ,page_size, snap->mems[num_mem].data + offset);
            }
            
        }  
    }

}

static struct ARMM_SNAPSHOT *org_snap,*new_snap;

#endif