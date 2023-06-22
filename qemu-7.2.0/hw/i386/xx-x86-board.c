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
#include "qemu/osdep.h"
#include <sys/param.h>
#include "target/i386/cpu.h"
#include <sys/resource.h>
#include <sys/shm.h>
#include "xx.h"

typedef uint64_t regval;

void xx_init_mem(MachineState *machine);


void xx_get_x86_cpu_state(struct X86_CPU_STATE *state)
{
    CPUState *cs = qemu_get_cpu(0);
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;
    for(int i = 0; i < 8 ;i ++)
    {
        state->regs[i] = env->regs[i];
    }
    state->eip = env->eip;
}
void xx_set_x86_cpu_state(struct X86_CPU_STATE *state)
{
    CPUState *cs = qemu_get_cpu(0);
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;
    for(int i = 0; i < 8 ;i ++)
    {
        env->regs[i] = state->regs[i];
    }
    env->eip = state->eip;
}
void* xx_save_x86_ctx_state()
{
    CPUX86State *env = g_new0(CPUX86State,1);
    CPUState *cs = qemu_get_cpu(0);
    X86CPU *cpu = X86_CPU(cs);
    memcpy(env,&cpu->env,offsetof(CPUX86State, end_reset_fields));
    return env;
}
void xx_restore_x86_ctx_state(void* state)
{
    CPUState *cs = qemu_get_cpu(0);
    X86CPU *cpu = X86_CPU(cs);
    memcpy(&cpu->env,state,offsetof(CPUX86State, end_reset_fields));
}
void xx_delete_x86_ctx_state(void* state)
{
    g_free(state);
}


struct XXX86MachineClass {
    X86MachineClass parent;
};
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
    type_register_static(&machine_xx_x86_typeinfo);    
}

type_init(machine_xx_register_types)