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

#define TYPE_XXFUZZER_MACHINE "xxfuzzer"
#define XX_MEM_REGIONS_MAX 256


struct XX_MemoryRegion
{
    char *name;
    hwaddr start;
    hwaddr size;
    int perm_read:1;
    int perm_write:1;
    int perm_exec:1;
    void *cb;

    void *user_data;
};



struct XX_MemoryRegion xx_ram_regions[XX_MEM_REGIONS_MAX];
int xx_num_ram_regions;
struct XX_MemoryRegion xx_mmio_regions[XX_MEM_REGIONS_MAX];
int xx_num_mmio_regions;


int get_xxfuzzer_cpu_type();


static void xxfuzzer_add_ram_regions(struct XX_MemoryRegion *region)
{
    if(xx_num_ram_regions >= XX_MEM_REGIONS_MAX)
        return;
    memcpy(&xx_ram_regions[xx_num_ram_regions++],region,sizeof(struct XX_MemoryRegion));
}
static void xxfuzzer_add_ram_regions(struct XX_MemoryRegion *region)
{
    if(xx_num_mmio_regions >= XX_MEM_REGIONS_MAX)
        return;
    memcpy(&xx_mmio_regions[xx_num_mmio_regions++],region,sizeof(struct XX_MemoryRegion));
}

static void xxfuzzer_init_mem(MachineState *machine)
{
    MemoryRegion *ram_space = get_system_memory();
    MemoryRegion *mmio_space = get_system_io();
    int i;
    for(i=0; i < xx_num_ram_region;i++)
    {
        MemoryRegion *mr = g_new0(MemoryRegion, 1);
	memory_region_init_ram(mr,NULL,xx_ram_regions[i].name,xx_ram_regions[i].size,0);
	memory_region_add_subregion(ram_space,xx_ram_regions[i].start,mr);
    }
    for(i=0; i < xx_num_ram_region;i++)
    {
	struct MemoryRegionOps ops;
        MemoryRegion *mr = g_new0(MemoryRegion, 1);
        memory_region_init_io(mr,NULL,&ops,xx_mmio_regions[i].user_data,x_mmio_regions[i].name,x_mmio_regions[i].size);
	memory_region_add_subregion(mmio_space,xx_mmio_regions[i].start,mr);
    }

    
}


static void machine_xxfuzzer_init(MachineState *mch)
{
    
    x86_cpus_init(0,0);
}

static void microvm_machine_reset(MachineState *machine, ShutdownCause reason)
{
    qemu_devices_reset(reason);
}
static void machine_xxfuzzer_class_init(ObjectClass *oc, void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);
    mc->desc = "xxfuzzer";
    mc->units_per_default_bus = 1;
    mc->has_hotpluggable_cpus = false;
    mc->no_floppy = 1;
    //mc->default_cpu_type = "qemu64-x86_64-cpu";
    mc->init = machine_xxfuzzer_init;
    mc->reset = microvm_machine_reset;
    mc->max_cpus = 1;
    mc->ignore_memory_transaction_failures = true;
    mc->default_ram_id = "xxfuzzer.mem";
}
static const TypeInfo machine_xxfuzzer_typeinfo = { 
        .name       = MACHINE_TYPE_NAME("xxfuzzer"), 
        .parent     = TYPE_MACHINE, 
        .class_init = machine_xxfuzzer_class_init, 
}; 
static void machine_xxfuzzer_register_types(void) 
{ 
        type_register_static(&machine_xxfuzzer_typeinfo); \
}
type_init(machine_xxfuzzer_register_types)
