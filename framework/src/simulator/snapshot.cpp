#include "config.h"
#include "snapshot.h"
#include "simulator.h"
#include "irq.h"

ARMM_SNAPSHOT *org_snap,*new_snap;



ARMM_SNAPSHOT* arm_take_snapshot()
{
    ARMM_SNAPSHOT *snap = (ARMM_SNAPSHOT*)malloc(sizeof(ARMM_SNAPSHOT));
    snap->mems = new vector<SNAPSHOT_MEM_SEG*>();
    snap->arm_ctx = save_arm_ctx_state();

    for(auto it = config->segs->begin(); it != config->segs->end(); it++)
    {
        if(!(*it)->readonly && (*it)->type == SEG_RAM)
        {
            snap->mems->push_back(new SNAPSHOT_MEM_SEG());
            snap->mems->back()->len = (*it)->size;
            snap->mems->back()->ptr = (*it)->ptr;
            snap->mems->back()->start = (*it)->start;
            snap->mems->back()->data = (uint8_t*)malloc(snap->mems->back()->len);
            memcpy(snap->mems->back()->data,snap->mems->back()->ptr,snap->mems->back()->len);
        }
    }

    return snap;    
}

void arm_restore_snapshot(ARMM_SNAPSHOT* snap)
{
    
    static uint8_t dirty_bits[0x1000];
    restore_arm_ctx_state(snap->arm_ctx);
    int page_size = target_pagesize();
    for(auto it = snap->mems->begin(); it != snap->mems->end(); it++)
    {
        int num_pages = (*it)->len / page_size;
        
        get_dirty_pages((*it)->start, (*it)->len, (unsigned long*)dirty_bits);
        for(int i = 0 ; i < num_pages ; i++)
        {
            if(1 & (dirty_bits[i / 8] >> (i & 7)))
            {
                uint32_t offset = page_size * i;
                memcpy((uint8_t*)(*it)->ptr + offset, (*it)->data + offset,page_size);
            }
            
        }  
    }

}




hw_addr snapshot_point = 0;

uint64_t mmio_read_snapshot(void *opaque,hw_addr addr,unsigned size)
{
    static bool found = false;
    if(!found)
    {
        ARM_CPU_STATE state;
        get_arm_cpu_state(&state);
        snapshot_point = state.regs[15];
        found = true;
    }
    return 0;
    
}
void mmio_write_snapshot(void *opaque,hw_addr addr,uint64_t data,unsigned size){}


bool exec_bbl_snapshot(hw_addr pc,uint32_t id)
{
    CMD_INFO cmd_info;
    int i;
    static bool returned = false;
    if(snapshot_point == pc)
    {
        
        irq_on_snapshot();
        register_exec_bbl_hook(arm_exec_bbl);
        
        for(auto it = config->segs->begin(); it != config->segs->end(); it++)
        {
            if((*it)->type != SEG_MMIO)
                continue;
            add_mmio_region((*it)->name,(*it)->start, (*it)->size, mmio_read_common, mmio_write_common,(void*)(uint64_t)(*it)->start);
        }
        new_snap = arm_take_snapshot();

        prepare_exit(EXIT_CTL_FORKSRV_UP);
        cmd_info = exit_with_code_get_cmd();
        if(cmd_info.cmd == CMD_FUZZ)
        {
            start_new();
        }
        else
        {
            printf("cmd %d after frk up not support\n",cmd_info.cmd);
            terminate_simulation();
        }

        return true;
    }
    else if(snapshot_point && !returned)
    {
       
        arm_restore_snapshot(org_snap);
        returned = true;
        return true;
    }
    #ifdef DBG
    fprintf(flog,"%d->bbl pc:%x\n",run_index,pc);
    #endif


    __afl_area_ptr[id] ++;
    return false;
}

