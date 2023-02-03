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
#include "xxfuzzer.h"
bool xxfuzzer_allowed;
#define TYPE_XXFUZZER_ACCEL ACCEL_CLASS_NAME("xxfuzzer")

static void xxfuzzer_accel_instance_init(Object *obj)
{
	;
}


static int xxfuzzer_init_machine(MachineState *ms)
{
    xxfuzzer_allowed = true;
    page_init();
    tb_htable_init();
    tcg_init(0, -1, 1);
    return 0;
}

static void xxfuzzer_accel_class_init(ObjectClass *oc, void *data)
{
    AccelClass *ac = ACCEL_CLASS(oc);
    ac->name = "xxfuzzer";
    ac->init_machine = xxfuzzer_init_machine;
    ac->allowed = &xxfuzzer_allowed;
}

static void xxfuzzer_accel_ops_init(AccelOpsClass *ops)
{
    ops->create_vcpu_thread = xxfuzzer_start_vcpu_thread;
    ops->kick_vcpu_thread = xxfuzzer_kick_vcpu_thread;
    ops->handle_interrupt = xxfuzzer_icount_handle_interrupt;
    ops->get_virtual_clock = xxfuzzer_icount_get;
    ops->get_elapsed_ticks = xxfuzzer_icount_get;
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
