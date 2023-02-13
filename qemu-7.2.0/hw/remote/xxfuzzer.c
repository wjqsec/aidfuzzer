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
#define TYPE_XXFUZZER_MACHINE "xxfuzzer"
#define XX_MEM_REGIONS_MAX 256

struct XXFuzzerMachineClass {
    X86MachineState parent;
};

struct XX_RAMRegion
{
    char *name;
    hwaddr start;
    hwaddr size;
};
struct XX_MMIORegion
{
    char *name;
    hwaddr start;
    hwaddr size;
    void *read_cb;
    void *write_cb;
};



struct XX_RAMRegion xx_ram_regions[XX_MEM_REGIONS_MAX];
int xx_num_ram_regions;
struct XX_MMIORegion xx_mmio_regions[XX_MEM_REGIONS_MAX];
int xx_num_mmio_regions;


int get_xxfuzzer_cpu_type();


static void xxfuzzer_add_ram_regions(char *name,hwaddr start, hwaddr size)
{
    if(xx_num_ram_regions >= XX_MEM_REGIONS_MAX)
        return;
    xx_ram_regions[xx_num_ram_regions].name = strdup(name);
    xx_ram_regions[xx_num_ram_regions].start = start;
    xx_ram_regions[xx_num_ram_regions].size = size;

}
static void xxfuzzer_add_mmio_regions(char *name, hwaddr start, hwaddr size, void *read_cb, void *write_cb)
{
    if(xx_num_mmio_regions >= XX_MEM_REGIONS_MAX)
        return;
    xx_mmio_regions[xx_num_mmio_regions].name = strdup(name);
    xx_mmio_regions[xx_num_mmio_regions].start = start;
    xx_mmio_regions[xx_num_mmio_regions].size = size;
    xx_mmio_regions[xx_num_mmio_regions].read_cb = read_cb;
    xx_mmio_regions[xx_num_mmio_regions].write_cb = write_cb;
}

static void xxfuzzer_init_mem(MachineState *machine)
{
    MemoryRegion *ram_space = get_system_memory();
    MemoryRegion *mmio_space = get_system_io();
    int i;
    for(i=0; i < xx_num_ram_regions;i++)
    {
        MemoryRegion *mr = g_new0(MemoryRegion, 1);
	memory_region_init_ram(mr,NULL,xx_ram_regions[i].name,xx_ram_regions[i].size,0);
	memory_region_add_subregion(ram_space,xx_ram_regions[i].start,mr);
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
    }

    
}


static void machine_xxfuzzer_init(MachineState *mch)
{
    X86MachineState *x86ms = X86_MACHINE(mch);
    //xxfuzzer_init_mem(mch);
    x86_cpus_init(x86ms,-1);
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
    mc->default_cpu_type = "qemu64-x86_64-cpu";
    mc->init = machine_xxfuzzer_init;
    mc->reset = microvm_machine_reset;
    mc->max_cpus = 1;
    mc->ignore_memory_transaction_failures = true;
    mc->default_ram_id = "xxfuzzer.mem";
}
static const TypeInfo machine_xxfuzzer_typeinfo = { 
        .name       = MACHINE_TYPE_NAME("xxfuzzer"), 
        .parent     = TYPE_X86_MACHINE, 
        .class_init = machine_xxfuzzer_class_init,
	.class_size    = sizeof(struct XXFuzzerMachineClass),
}; 
static void machine_xxfuzzer_register_types(void) 
{ 
        type_register_static(&machine_xxfuzzer_typeinfo); \
}
type_init(machine_xxfuzzer_register_types)
