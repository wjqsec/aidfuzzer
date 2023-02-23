#include "qemu/osdep.h"
#include "cpu.h"
#include "elf.h"
#include "sysemu/dump.h"
#include "hw/boards.h"
typedef uint64_t regval;

void xx_init_mem(MachineState *machine);

struct ARM_CPU_STATE
{
    regval eip;
};
void xx_get_arm_cpu_state(struct ARM_CPU_STATE *state)
{
    CPUState *cs = qemu_get_cpu(0);
    ARMCPU *cpu = ARM_CPU(cs);
    CPUARMState *env = &cpu->env;
    state->eip = env->pc;  
}
void xx_set_arm_cpu_state(struct ARM_CPU_STATE *state)
{
    CPUState *cs = qemu_get_cpu(0);
    ARMCPU *cpu = ARM_CPU(cs);
    CPUARMState *env = &cpu->env;
    env->pc = state->eip;
    
}

struct XXARMMachineClass {
     MachineClass parent;
};
static void machine_xx_arm_init(MachineState *mch)
{
    xx_init_mem(mch);
    Object *cpuobj = object_new(ARM_CPU_TYPE_NAME("cortex-a9"));
    qdev_realize(DEVICE(cpuobj), NULL, NULL);
}
static void xx_arm_machine_reset(MachineState *machine, ShutdownCause reason)
{
    qemu_devices_reset(reason);
}
static void machine_xx_arm_class_init(ObjectClass *oc, void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);
    mc->desc = "xx";
    mc->units_per_default_bus = 1;
    mc->has_hotpluggable_cpus = false;
    mc->no_floppy = 1;
    mc->default_cpu_type = "";
    mc->init = machine_xx_arm_init;
    mc->reset = xx_arm_machine_reset;
    mc->max_cpus = 1;
    mc->ignore_memory_transaction_failures = true;
    mc->default_ram_id = "xx.mem";
    mc->default_ram_size = 0xffffffff;
}




static const TypeInfo machine_xx_arm_typeinfo = { 
    .name       = MACHINE_TYPE_NAME("xx"), 
    .parent     = TYPE_MACHINE, 
    .class_init = machine_xx_arm_class_init,
	.class_size    = sizeof(struct XXARMMachineClass),
}; 

static void machine_xx_register_types(void) 
{
    type_register_static(&machine_xx_arm_typeinfo);    
}

type_init(machine_xx_register_types)