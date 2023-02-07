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

static void machine_xxfuzzer_init(MachineState *mch)
{
    CPUState *cpu = NULL;

    /* Initialize CPU (if user asked for it) */
    if (mch->cpu_type) {
        cpu = cpu_create(mch->cpu_type);
        if (!cpu) {
            error_report("Unable to initialize CPU");
            exit(1);
        }
    }

    /* RAM at address zero */
    if (mch->ram) {
        memory_region_add_subregion(get_system_memory(), 0, mch->ram);
    }

    if (mch->kernel_filename) {
        error_report("The -kernel parameter is not supported "
                     "(use the generic 'loader' device instead).");
        exit(1);
    }
}
static void machine_xxfuzzer_class_init(ObjectClass *oc, void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);
    /*
    mc->desc = "xxfuzzer";
    mc->init = machine_xxfuzzer_init;
    mc->max_cpus = 1;
    mc->ignore_memory_transaction_failures = true;
    mc->default_ram_id = "xxfuzzer.mem";
    */
    mc->desc = "empty machine";
    mc->init = machine_xxfuzzer_init;
    mc->max_cpus = 1;
    mc->default_ram_size = 0;
    mc->default_ram_id = "ram";
    mc->no_serial = 1;
    mc->no_parallel = 1;
    mc->no_floppy = 1;
    mc->no_cdrom = 1;
    mc->no_sdcard = 1;
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
