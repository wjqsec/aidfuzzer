#ifndef SNAPSHOT_INCLUDED
#define SNAPSHOT_INCLUDED

#include <vector>
using namespace std;

struct SNAPSHOT_MEM_SEG
{
    uint8_t *data;
    hw_addr start;
    hw_addr len;
};

struct ARMM_SNAPSHOT
{
    void *arm_ctx;
    vector<SNAPSHOT_MEM_SEG*> *mems;
    
};

ARMM_SNAPSHOT* arm_take_snapshot();
void arm_restore_snapshot(ARMM_SNAPSHOT* snap);

uint64_t mmio_read_snapshot(void *opaque,hw_addr addr,unsigned size);
void mmio_write_snapshot(void *opaque,hw_addr addr,uint64_t data,unsigned size);
bool exec_bbl_snapshot(hw_addr pc,uint32_t id);
#endif