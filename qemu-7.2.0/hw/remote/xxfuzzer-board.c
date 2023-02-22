#include "qemu/osdep.h"

#include "hw/remote/machine.h"
#include "exec/memory.h"
#include "qapi/error.h"
#include "hw/pci/pci_host.h"
#include "hw/remote/iohub.h"
#include "hw/remote/iommu.h"
#include "hw/qdev-core.h"
#include "hw/remote/iommu.h"
#include "hw/remote/vfio-user-obj.h"
#include "hw/pci/msi.h"
#include "hw/boards.h"
#include "hw/i386/x86.h"
#include "exec/ramblock.h"

struct DirtyBitmapSnapshot {
    ram_addr_t start;
    ram_addr_t end;
    unsigned long dirty[];
};
enum XX_CPU_TYPE 
{
    X86,
    ARM
};
enum XX_CPU_TYPE get_xx_cpu_type();


struct XXX86MachineClass {
    X86MachineState parent;
};

struct XX_RAMRegion
{
    char *name;
    hwaddr start;
    hwaddr size;
    MemoryRegion *mr;
};
struct XX_MMIORegion
{
    char *name;
    hwaddr start;
    hwaddr size;
    void *read_cb;
    void *write_cb;
    MemoryRegion *mr;
};


#define XX_MEM_REGIONS_MAX 256
struct XX_RAMRegion xx_ram_regions[XX_MEM_REGIONS_MAX];
int xx_num_ram_regions;
struct XX_MMIORegion xx_mmio_regions[XX_MEM_REGIONS_MAX];
int xx_num_mmio_regions;



MemTxResult xx_ram_rw(hwaddr addr,hwaddr len,void *buf, bool is_write)
{
    if (is_write) {
        return address_space_write(&address_space_memory, addr, MEMTXATTRS_UNSPECIFIED, buf, len);
    } else {
        return address_space_read_full(&address_space_memory, addr, MEMTXATTRS_UNSPECIFIED, buf, len);
    }
}

static bool check_mem_overlap(hwaddr start, hwaddr size)
{
    int i;
    hwaddr end = start + size;
    for(i=0; i < xx_num_ram_regions;i++)
    {
        if(
            !(start > xx_ram_regions[i].start + xx_ram_regions[i].size || end < xx_ram_regions[i].start)
        )
        return true;
    }
    for(i=0; i < xx_num_mmio_regions;i++)
    {
        if(
            !(start > xx_mmio_regions[i].start + xx_mmio_regions[i].size || end < xx_mmio_regions[i].start)
        )
        return true;
    }
    return false;
}
static bool check_mem_addr_and_size(hwaddr start, hwaddr size)
{
    if(start & (qemu_target_page_size() -1) != 0 || size & (qemu_target_page_size() - 1) != 0)
    {
        return false;
    }
    return true;
}
static MemoryRegion *find_mr_by_addr(hwaddr start, hwaddr size)
{
    MemoryRegion *mr = NULL;
    int i;
    for(i=0; i < xx_num_ram_regions;i++)
    {
        if(start >= xx_ram_regions[i].start && start + size <= xx_ram_regions[i].start + xx_ram_regions[i].size)
        {
            mr = xx_ram_regions[i].mr;
        }
    }
    for(i=0; i < xx_num_mmio_regions;i++)
    {
        if(start >= xx_mmio_regions[i].start && start + size <= xx_mmio_regions[i].start + xx_mmio_regions[i].size)
        {
            mr = xx_mmio_regions[i].mr;
        }
    }
    return mr;
}

void xx_add_ram_regions(char *name,hwaddr start, hwaddr size)
{
    if(xx_num_ram_regions >= XX_MEM_REGIONS_MAX)
        return;
    if(check_mem_overlap(start,size))
        return;
    if(!check_mem_addr_and_size(start,size))
        return;
    xx_ram_regions[xx_num_ram_regions].name = strdup(name);
    xx_ram_regions[xx_num_ram_regions].start = start;
    xx_ram_regions[xx_num_ram_regions].size = size;
    xx_num_ram_regions++;

}
void xx_add_mmio_regions(char *name, hwaddr start, hwaddr size, void *read_cb, void *write_cb)
{
    if(xx_num_mmio_regions >= XX_MEM_REGIONS_MAX)
        return;
    if(check_mem_overlap(start,size))
        return;
    if(!check_mem_addr_and_size(start,size))
        return;
    xx_mmio_regions[xx_num_mmio_regions].name = strdup(name);
    xx_mmio_regions[xx_num_mmio_regions].start = start;
    xx_mmio_regions[xx_num_mmio_regions].size = size;
    xx_mmio_regions[xx_num_mmio_regions].read_cb = read_cb;
    xx_mmio_regions[xx_num_mmio_regions].write_cb = write_cb;
    xx_num_mmio_regions++;
}

RAMBlock *qemu_get_ram_block(ram_addr_t addr);
void xx_clear_dirty_mem(ram_addr_t addr, ram_addr_t size)
{
    RAMBlock *block = qemu_get_ram_block(addr);
    MemoryRegion *mr = block->mr;

    tlb_reset_dirty_range_all(addr, size);
    memory_region_clear_dirty_bitmap(mr, 0, size);
    printf("clear dirty pages %p-%p\n",addr,addr+size);
}
void xx_get_dirty_pages(hwaddr addr,hwaddr size, unsigned long dirty[])
{
    int num_page_in_byte = 0;
    if(!check_mem_addr_and_size(addr,size))
        return;
    MemoryRegion *mr = find_mr_by_addr(addr,size);
    if(!mr)
        return;
    DirtyBitmapSnapshot * snap = memory_region_snapshot_and_clear_dirty(mr,addr - mr->addr , size, DIRTY_MEMORY_VGA);
    num_page_in_byte = ((size / qemu_target_page_size()) / 8) + ((size / qemu_target_page_size()) % 8) ? 1 : 0 ;

    memcpy(dirty,snap->dirty,num_page_in_byte);
    g_free(snap);
    printf("get dirty pages %p-%p\n",addr,addr+size);
}


static void xx_init_mem(MachineState *machine)
{
    MemoryRegion *ram_space = get_system_memory();
    MemoryRegion *mmio_space = get_system_io();
    int i;
    for(i=0; i < xx_num_ram_regions;i++)
    {
        MemoryRegion *mr = g_new0(MemoryRegion, 1);
        memory_region_init_ram(mr,NULL,xx_ram_regions[i].name,xx_ram_regions[i].size,0);
        memory_region_add_subregion(ram_space,xx_ram_regions[i].start,mr);
        xx_ram_regions[i].mr = mr;
        printf("add ram %p-%p %s\n",xx_ram_regions[i].start, xx_ram_regions[i].start+xx_ram_regions[i].size, xx_ram_regions[i].name);
    }
    for(i=0; i < xx_num_mmio_regions;i++)
    {
        struct MemoryRegionOps ops;
        ops.read = xx_mmio_regions[i].read_cb;
        ops.write = xx_mmio_regions[i].write_cb;
        ops.read_with_attrs = 0;
        ops.write_with_attrs = 0;
        ops.endianness = DEVICE_NATIVE_ENDIAN;
        ops.valid.min_access_size = 1;
        ops.valid.max_access_size = 8;
        ops.valid.unaligned = true;
        ops.valid.accepts = NULL;
        ops.impl.min_access_size = 1;
        ops.impl.max_access_size = 8;
        ops.impl.unaligned = true;
        MemoryRegion *mr = g_new0(MemoryRegion, 1);
        memory_region_init_io(mr,NULL,&ops,NULL,xx_mmio_regions[i].name,xx_mmio_regions[i].size);
	    memory_region_add_subregion(mmio_space,xx_mmio_regions[i].start,mr);
        xx_mmio_regions[i].mr = mr;
        printf("add mmio %p-%p %s\n",xx_mmio_regions[i].start, xx_mmio_regions[i].start+xx_mmio_regions[i].size, xx_mmio_regions[i].name);
    }
}


static void machine_xx_x86_init(MachineState *mch)
{
    X86MachineState *x86ms = X86_MACHINE(mch);
    xx_init_mem(mch);
    x86_cpus_init(x86ms,-1);
}
static void xx_x86_machine_reset(MachineState *machine, ShutdownCause reason)
{
    qemu_devices_reset(reason);
}
static void machine_xx_x86_class_init(ObjectClass *oc, void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);
    mc->desc = "xx";
    mc->units_per_default_bus = 1;
    mc->has_hotpluggable_cpus = false;
    mc->no_floppy = 1;
    mc->default_cpu_type = "qemu64-x86_64-cpu";
    mc->init = machine_xx_x86_init;
    mc->reset = xx_x86_machine_reset;
    mc->max_cpus = 1;
    mc->ignore_memory_transaction_failures = true;
    mc->default_ram_id = "xx.mem";
    mc->default_ram_size = 0xffffffff;
}


static const TypeInfo machine_xx_x86_typeinfo = { 
    .name       = MACHINE_TYPE_NAME("xx"), 
    .parent     = TYPE_X86_MACHINE, 
    .class_init = machine_xx_x86_class_init,
	.class_size    = sizeof(struct XXX86MachineClass),
}; 
static void machine_xx_register_types(void) 
{
    enum XX_CPU_TYPE type = get_xx_cpu_type();
    switch (type)
    {
        case X86:
        type_register_static(&machine_xx_x86_typeinfo);
        break;
        case ARM:
        break;
    }       
}
type_init(machine_xx_register_types)
