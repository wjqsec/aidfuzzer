#include "qemu/osdep.h"
#include "qemu/rcu.h"
#include "qapi/error.h"
#include "qemu/module.h"
#include "qemu/option.h"
#include "qemu/config-file.h"
#include "qemu/accel.h"
#include "sysemu/qtest.h"
#include "sysemu/cpus.h"
#include "sysemu/cpu-timers.h"
#include "qemu/guest-random.h"
#include "qemu/main-loop.h"
#include "hw/core/cpu.h"
#include "tcg/tcg.h"
#include "xxfuzzer.h"
extern bool tcg_allowed;
int xxfuzzer_cpu_type;

int get_xxfuzzer_cpu_type()
{
    return xxfuzzer_cpu_type;
}
void set_xxfuzzer_cpu_type(int type)
{
    xxfuzzer_cpu_type = type;
}
//extern TCGContext *tcg_ctx;
#define TYPE_XXFUZZER_ACCEL ACCEL_CLASS_NAME("xxfuzzer")

static void xxfuzzer_accel_instance_init(Object *obj)
{
	;
}


static int xxfuzzer_init_machine(MachineState *ms)
{
    tcg_allowed = true;
    page_init();
    tb_htable_init();
    tcg_init(0, -1, 1);
    #if defined(CONFIG_SOFTMMU)
    /*
     * There's no guest base to take into account, so go ahead and
     * initialize the prologue now.
     */
    tcg_prologue_init(tcg_ctx);
    #endif
    return 0;
}

static void xxfuzzer_accel_class_init(ObjectClass *oc, void *data)
{
    AccelClass *ac = ACCEL_CLASS(oc);
    ac->name = "xxfuzzer";
    ac->init_machine = xxfuzzer_init_machine;
    ac->allowed = &tcg_allowed;
}


bool tcg_supports_guest_debug(void);
void tcg_remove_all_breakpoints(CPUState *cpu);
int tcg_remove_breakpoint(CPUState *cs, int type, hwaddr addr, hwaddr len);
int tcg_insert_breakpoint(CPUState *cs, int type, hwaddr addr, hwaddr len);

static void xxfuzzer_accel_ops_init(AccelOpsClass *ops)
{
    ops->create_vcpu_thread = xxfuzzer_start_vcpu_thread;
    ops->kick_vcpu_thread = xxfuzzer_kick_vcpu_thread;
    ops->handle_interrupt = xxfuzzer_icount_handle_interrupt;
    ops->get_virtual_clock = xxfuzzer_icount_get;
    ops->get_elapsed_ticks = xxfuzzer_icount_get;

    ops->supports_guest_debug = tcg_supports_guest_debug;
    ops->insert_breakpoint = tcg_insert_breakpoint;
    ops->remove_breakpoint = tcg_remove_breakpoint;
    ops->remove_all_breakpoints = tcg_remove_all_breakpoints;
}

static void xxfuzzer_accel_ops_class_init(ObjectClass *oc, void *data)
{
    AccelOpsClass *ops = ACCEL_OPS_CLASS(oc);

    ops->ops_init = xxfuzzer_accel_ops_init;
}
static const TypeInfo xxfuzzer_accel_type = {
    .name = TYPE_XXFUZZER_ACCEL,
    .parent = TYPE_ACCEL,
    .instance_init = xxfuzzer_accel_instance_init,
    .class_init = xxfuzzer_accel_class_init,
    .instance_size = 1024,
};

static const TypeInfo xxfuzzer_accel_ops_type = {
    .name = ACCEL_OPS_NAME("xxfuzzer"),
    .parent = TYPE_ACCEL_OPS,
    .class_init = xxfuzzer_accel_ops_class_init,
    .abstract = true,
};

static void xxfuzzer_type_init(void)
{
    type_register_static(&xxfuzzer_accel_type);
}
static void xxfuzzer_accel_ops_register_types(void)
{
    type_register_static(&xxfuzzer_accel_ops_type);
}
type_init(xxfuzzer_accel_ops_register_types);
type_init(xxfuzzer_type_init);
