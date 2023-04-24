#include "qemu/osdep.h"
#include "cpu.h"
#include "elf.h"
#include "sysemu/dump.h"
#include "hw/boards.h"
#include "qemu/error-report.h"
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/boards.h"
#include "hw/qdev-properties.h"
#include "hw/qdev-clock.h"
#include "qemu/error-report.h"
#include "hw/arm/stm32f205_soc.h"
#include "hw/arm/boot.h"
#include "sysemu/reset.h"

#define SYSCLK_FRQ 25000000
#define REFCLK_FRQ (1 * 1000 * 1000)
typedef uint64_t regval;
MemoryRegion *get_system_memory(void);
#define TYPE_XX_MACHINE "xx"
void xx_init_mem(MachineState *machine);
uint64_t vecbase = 0;
struct ARM_CPU_STATE
{
    uint32_t regs[16];
    uint64_t xregs[32];
};
struct ARM_NVIC_ALL_STATE
{
    CPUARMState *env;
    struct NVICState *nvic;
};

void xx_set_armv7_vecbase(uint64_t addr)
{
    vecbase = addr;
}
void xx_insert_nvic_intc(int irq, bool secure)
{
    CPUState *cs = qemu_get_cpu(0);
    ARMCPU *cpu = ARM_CPU(cs);
    CPUARMState *env = &cpu->env;
    //NVICState *nvic_state = cpu->env.nvic;
    //qemu_mutex_lock_iothread();
    
    if(armv7m_nvic_get_ready_status(env->nvic, irq, secure))
    {
        armv7m_nvic_set_pending(env->nvic, irq, secure);
        //qemu_mutex_unlock_iothread();
    }
        
}
uint32_t* xx_get_enabled_nvic_irq2(uint16_t **irqs)
{
    CPUState *cs = qemu_get_cpu(0);
    ARMCPU *cpu = ARM_CPU(cs);
    CPUARMState *env = &cpu->env;
    NVICState *nvic_state = env->nvic;
    *irqs = nvic_state->enabled_irqs;
    return &nvic_state->enabled_irqs_idx;

}


GArray* xx_get_enabled_nvic_irq()
{
    GArray* ret = g_array_new(FALSE, FALSE, sizeof(int));
    CPUState *cs = qemu_get_cpu(0);
    ARMCPU *cpu = ARM_CPU(cs);
    NVICState *nvic_state = cpu->env.nvic;
    for(int i= 15; i < NVIC_MAX_VECTORS; i ++)
    {
	    if(nvic_state->vectors[i].enabled)
		    g_array_append_val(ret, i);
    }
    return ret;
}

void xx_get_arm_cpu_state(struct ARM_CPU_STATE *state)
{
    int i;
    CPUState *cs = qemu_get_cpu(0);
    ARMCPU *cpu = ARM_CPU(cs);
    CPUARMState *env = &cpu->env;
    for(i = 0 ;i < 16 ; i++)
    {
        state->regs[i] = env->regs[i];
    }
    for(i = 0 ; i < 32 ; i++)
    {
        state->xregs[i] = env->xregs[i];
    }
}
void xx_set_arm_cpu_state(struct ARM_CPU_STATE *state)
{
    int i;
    CPUState *cs = qemu_get_cpu(0);
    ARMCPU *cpu = ARM_CPU(cs);
    CPUARMState *env = &cpu->env;
    for(i = 0 ;i < 16 ; i++)
    {
        env->regs[i] = state->regs[i];
    }
    for(i = 0 ; i < 32 ; i++)
    {
        env->xregs[i] = state->xregs[i];
    }
}
void xx_reset_arm_reg()
{
    cpu_reset(ARM_CPU(first_cpu));
}
void* xx_save_arm_ctx_state()
{
    struct ARM_NVIC_ALL_STATE *ret = g_new0(struct ARM_NVIC_ALL_STATE,1);
    CPUARMState *env = g_new0(CPUARMState,1);
    struct NVICState *nvic = g_new0(struct NVICState,1);
    CPUState *cs = qemu_get_cpu(0);
    ARMCPU *cpu = ARM_CPU(cs);
    memcpy(env,&cpu->env,offsetof(CPUARMState, end_reset_fields));
    memcpy(nvic,cpu->env.nvic,sizeof(struct NVICState));
    ret->env = env;
    ret->nvic = nvic;
    return ret;
}
void xx_restore_arm_ctx_state(void* state)
{
    struct ARM_NVIC_ALL_STATE *ret = (struct ARM_NVIC_ALL_STATE *)state;
    CPUState *cs = qemu_get_cpu(0);
    ARMCPU *cpu = ARM_CPU(cs);
    memcpy(&cpu->env,ret->env,offsetof(CPUARMState, end_reset_fields));
    memcpy(cpu->env.nvic,ret->nvic,sizeof(struct NVICState));
}
void xx_delete_arm_ctx_state(void* state)
{
    struct ARM_NVIC_ALL_STATE *ret = (struct ARM_NVIC_ALL_STATE *)state;
    g_free(ret->env);
    g_free(ret->nvic);
    g_free(ret);
}
struct XXARMMachineClass {
    MachineClass parent;

};
struct XXARMMachineState {
    MachineState parent;

    ARMv7MState armv7m;
    Clock *sysclk;
    Clock *refclk;
};
OBJECT_DECLARE_TYPE(XXARMMachineState, XXARMMachineClass, XX_MACHINE)

static void machine_xx_arm_init(MachineState *mch)
{
    XXARMMachineState *mms = XX_MACHINE(mch);
    XXARMMachineClass *mmc = XX_MACHINE_GET_CLASS(mch);
    MachineClass *mc = MACHINE_GET_CLASS(mch);
    DeviceState *armv7m;
    MemoryRegion *system_memory = get_system_memory();
    xx_init_mem(mch);
    mms->sysclk = clock_new(OBJECT(mch), "SYSCLK");
    clock_set_hz(mms->sysclk, SYSCLK_FRQ);
    mms->refclk = clock_new(OBJECT(mch), "REFCLK");
    clock_set_hz(mms->refclk, REFCLK_FRQ);

    object_initialize_child(OBJECT(mms), "armv7m", &mms->armv7m, TYPE_ARMV7M);
    armv7m = DEVICE(&mms->armv7m);

    qdev_connect_clock_in(armv7m, "cpuclk", mms->sysclk);
    qdev_connect_clock_in(armv7m, "refclk", mms->refclk);
    qdev_prop_set_string(armv7m, "cpu-type", mc->default_cpu_type);

    object_property_set_link(OBJECT(&mms->armv7m), "memory",
                             OBJECT(system_memory), &error_abort);
    sysbus_realize(SYS_BUS_DEVICE(&mms->armv7m), &error_fatal);
    CPUState *cs = qemu_get_cpu(0);
    ARMCPU *cpu = ARM_CPU(cs);
    cpu->init_svtor = vecbase;
    cpu->init_nsvtor = vecbase;

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
    mc->default_cpu_type = ARM_CPU_TYPE_NAME("cortex-m7");
    mc->init = machine_xx_arm_init;
    mc->reset = xx_arm_machine_reset;
    mc->max_cpus = 1;
    //mc->ignore_memory_transaction_failures = true;
    mc->default_ram_id = "xx.mem";
    mc->default_ram_size = 0xffffffff;

}




static const TypeInfo machine_xx_arm_typeinfo = { 
    .name       = MACHINE_TYPE_NAME("xx"), 
    .parent     = TYPE_MACHINE, 
    .class_init = machine_xx_arm_class_init,
	.class_size    = sizeof(struct XXARMMachineClass),
    .instance_size = sizeof(struct XXARMMachineState),
}; 

static void machine_xx_register_types(void) 
{
    type_register_static(&machine_xx_arm_typeinfo);    
}

type_init(machine_xx_register_types)
