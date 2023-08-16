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
#include "xx.h"
extern int64_t bbl_counts;
#define SYSCLK_FRQ 25000000
#define REFCLK_FRQ (1 * 1000 * 1000)

MemoryRegion *get_system_memory(void);
#define TYPE_XX_MACHINE "xx"

static CPUARMState *env;
static struct NVICState *nvic;
static CPUState *cs;
static ARMCPU *cpu;


struct ARM_NVIC_ALL_STATE
{
    CPUARMState *env;
    struct NVICState *nvic;
};


void xx_set_armv7_vecbase(uint64_t vecbase)
{
    cpu->init_svtor = vecbase;
    cpu->init_nsvtor = vecbase;
}
uint64_t xx_get_arm_precise_pc(void)
{
    return cs->precise_pc;
}
bool xx_insert_nvic_intc(int irq)
{
    //if(armv7m_nvic_get_ready_status(nvic, irq, secure))
    if(nvic->vectors[irq].enabled && !nvic->vectors[irq].pending)
    {
        armv7m_nvic_set_pending(nvic, irq, false);
        return true;
    }   
    return false;
}
bool xx_get_arm_v7m_is_handler_mode(void)
{
    return env->v7m.exception != 0;
}
uint32_t* xx_get_enabled_nvic_irq2(uint16_t **irqs)
{
    *irqs = nvic->enabled_irqs;
    return &nvic->enabled_irqs_idx;

}


GArray* xx_get_enabled_nvic_irq(void)
{
    GArray* ret = g_array_new(FALSE, FALSE, sizeof(int));

    for(int i= 15; i < NVIC_MAX_VECTORS; i ++)
    {
	    if(nvic->vectors[i].enabled)
		    g_array_append_val(ret, i);
    }
    return ret;
}

void xx_get_arm_cpu_state(struct ARM_CPU_STATE *state)
{
    int i;
    for(i = 0 ;i < 16 ; i++)
    {
        state->regs[i] = env->regs[i];
    }
    for(i = 0 ; i < 32 ; i++)
    {
        state->xregs[i] = env->xregs[i];
    }
    
    state->xpsr = xpsr_read(env);
}
void xx_set_arm_cpu_state(struct ARM_CPU_STATE *state)
{
    int i;
    for(i = 0 ;i < 16 ; i++)
    {
        env->regs[i] = state->regs[i];
    }
    for(i = 0 ; i < 32 ; i++)
    {
        env->xregs[i] = state->xregs[i];
    }
}
void xx_reset_arm_reg(void)
{
    cpu_reset(CPU(ARM_CPU(first_cpu)));
}
void* xx_save_arm_ctx_state(void)
{
    struct ARM_NVIC_ALL_STATE *ret = g_new0(struct ARM_NVIC_ALL_STATE,1);
    CPUARMState *env_ret = g_new0(CPUARMState,1);
    struct NVICState *nvic_ret = g_new0(struct NVICState,1);

    memcpy(env_ret,&cpu->env,offsetof(CPUARMState, end_reset_fields));
    memcpy(nvic_ret,cpu->env.nvic,sizeof(struct NVICState));
    ret->env = env_ret;
    ret->nvic = nvic_ret;
    return ret;
}
void xx_restore_arm_ctx_state(void* state)
{
    bbl_counts = 1;
    //qemu_devices_reset(SHUTDOWN_CAUSE_SNAPSHOT_LOAD);
    struct ARM_NVIC_ALL_STATE *ret = (struct ARM_NVIC_ALL_STATE *)state;
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
    cs = qemu_get_cpu(0);
    cpu = ARM_CPU(cs);
    env = &cpu->env;
    nvic = cpu->env.nvic;
    

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
