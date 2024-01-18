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
#include "hw/intc/armv7m_nvic.h"
#include "xx.h"

#define SYSCLK_FRQ 25000000
#define REFCLK_FRQ (1 * 1000 * 1000)

MemoryRegion *get_system_memory(void);
#define TYPE_XX_MACHINE "xx"

CPUARMState *xx_env;
struct NVICState *xx_nvic;
CPUState *xx_cs;
ARMCPU *xx_cpu;

hw_addr precise_pc;

typedef struct _ARM_NVIC_ALL_STATE
{
    CPUARMState *env;
    struct NVICState *nvic;
}ARM_NVIC_ALL_STATE;


void set_armv7_init_vecbase(hw_addr addr)
{
    xx_cpu->init_svtor = addr;
    xx_cpu->init_nsvtor = addr;
}
hw_addr get_arm_precise_pc(void)
{
    return xx_cs->precise_pc;
}
hw_addr get_arm_pc(void)
{
    return xx_env->regs[15];
}
hw_addr get_nvic_vecbase(void)
{
    return xx_env->v7m.vecbase[M_REG_NS];
}
bool insert_nvic_intc(irq_val irq)
{
    if(xx_nvic->vectors[irq].enabled && !xx_nvic->vectors[irq].pending)
    {
        armv7m_nvic_set_pending(xx_nvic, irq, false);
        return true;
    }   
    return false;
}
irq_val get_arm_v7m_is_handler_mode(void)
{
    return xx_env->v7m.exception;
}

irq_val get_enabled_nvic_irq(irq_val **irqs)
{
    *irqs = xx_nvic->enabled_irqs;
    return xx_nvic->enabled_irqs_idx;

}

reg_val get_arm_lr(void)
{
    return xx_env->regs[14];
}

void get_arm_cpu_state(ARM_CPU_STATE *state)
{
    int i;
    for(i = 0 ;i < 16 ; i++)
    {
        state->regs[i] = xx_env->regs[i];
    }
    for(i = 0 ; i < 32 ; i++)
    {
        state->xregs[i] = xx_env->xregs[i];
    }
    
    state->xpsr = xpsr_read(xx_env);
}
void set_arm_cpu_state(ARM_CPU_STATE *state)
{
    int i;
    for(i = 0 ;i < 16 ; i++)
    {
        xx_env->regs[i] = state->regs[i];
    }
    for(i = 0 ; i < 32 ; i++)
    {
        xx_env->xregs[i] = state->xregs[i];
    }
}
void reset_arm_reg(void)
{
    cpu_reset(CPU(ARM_CPU(first_cpu)));
}
void* save_arm_ctx_state(void)
{
    ARM_NVIC_ALL_STATE *ret = g_new0(ARM_NVIC_ALL_STATE,1);
    CPUARMState *env_ret = g_new0(CPUARMState,1);
    struct NVICState *nvic_ret = g_new0(struct NVICState,1);

    memcpy(env_ret,&xx_cpu->env,offsetof(CPUARMState, end_reset_fields));
    memcpy(nvic_ret,xx_cpu->env.nvic,sizeof(struct NVICState));
    ret->env = env_ret;
    ret->nvic = nvic_ret;
    return ret;
}
void restore_arm_ctx_state(void* state)
{
    bbl_counts = 1;
    ARM_NVIC_ALL_STATE *ret = (ARM_NVIC_ALL_STATE *)state;
    memcpy(&xx_cpu->env,ret->env,offsetof(CPUARMState, end_reset_fields));
    memcpy(xx_cpu->env.nvic,ret->nvic,sizeof(struct NVICState));
}
void delete_arm_ctx_state(void* state)
{
    ARM_NVIC_ALL_STATE *ret = (ARM_NVIC_ALL_STATE *)state;
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
    //XXARMMachineClass *mmc = XX_MACHINE_GET_CLASS(mch);
    MachineClass *mc = MACHINE_GET_CLASS(mch);
    DeviceState *armv7m;
    MemoryRegion *system_memory = get_system_memory();

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
    xx_cs = qemu_get_cpu(0);
    xx_cpu = ARM_CPU(xx_cs);
    xx_env = &xx_cpu->env;
    xx_nvic = xx_cpu->env.nvic;
    

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
