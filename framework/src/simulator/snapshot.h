#ifndef SNAPSHOT_INCLUDED
#define SNAPSHOT_INCLUDED

typedef struct _SNAPSHOT_MEM_SEG
{
    uint8_t *data;
    hw_addr start;
    uint32_t len;
}SNAPSHOT_MEM_SEG;

typedef struct _ARMM_SNAPSHOT
{
    int num_segs;
    SNAPSHOT_MEM_SEG mems[MAX_NUM_MEM_REGION];
    void *arm_ctx;
}ARMM_SNAPSHOT;

ARMM_SNAPSHOT* arm_take_snapshot();
void arm_restore_snapshot(ARMM_SNAPSHOT* snap);

uint64_t mmio_read_snapshot(void *opaque,hw_addr addr,unsigned size);
void mmio_write_snapshot(void *opaque,hw_addr addr,uint64_t data,unsigned size);
bool exec_bbl_snapshot(hw_addr pc,uint32_t id);
#endif