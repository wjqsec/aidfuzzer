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
#include "exec/exec-all.h"
typedef uint64_t regval;
enum XX_CPU_TYPE 
{
    X86,
    ARM
};
typedef void (*exec_bbl_cb)(); 
exec_bbl_cb exec_bbl_func;
bool tcg_supports_guest_debug(void);
void tcg_remove_all_breakpoints(CPUState *cpu);
int tcg_remove_breakpoint(CPUState *cs, int type, hwaddr addr, hwaddr len);
int tcg_insert_breakpoint(CPUState *cs, int type, hwaddr addr, hwaddr len);


extern bool tcg_allowed;

enum XX_CPU_TYPE xx_cpu_type;
enum XX_CPU_TYPE get_xx_cpu_type(){ return xx_cpu_type; }
void set_xx_cpu_type(enum XX_CPU_TYPE type) { xx_cpu_type = type; }



void xx_register_exec_bbl_hook(exec_bbl_cb cb)
{
    exec_bbl_func = cb;
}

//-------------------x86
struct X86_CPU_STATE
{
    regval eip;
};
void xx_get_x86_cpu_state(struct X86_CPU_STATE *state)
{
    CPUState *cs = qemu_get_cpu(0);
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;
    state->eip = env->eip;
}
void xx_set_x86_cpu_state(struct X86_CPU_STATE *state)
{
    CPUState *cs = qemu_get_cpu(0);
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;
    env->eip = state->eip;
}


int xx_thread_loop(bool debug)
{
    int r;
    CPUState *cpu = qemu_get_cpu(0);
    static bool init = false; 
    if(!init)
    {
		cpu->thread_id = qemu_get_thread_id();
        cpu->can_do_io = 1;
        cpu->created = true;
        cpu->exit_request = false;
        
        tcg_register_thread();
        qemu_guest_random_seed_thread_part2(0);
		//set_do_interrupt_hook
        init = true;
    }
    //qemu_mutex_unlock_iothread();
    while(!cpu->stop && !cpu->exit_request)
    {
        if(!cpu_work_list_empty(cpu))
	        process_queued_cpu_work(cpu);
		if(debug)
			main_loop_wait(true);
		if(cpu_can_run(cpu))
		{
			cpu_exec_start(cpu);
			//CPUClass *cc = CPU_GET_CLASS(cpu);
			r = cpu_exec(cpu);
			cpu_exec_end(cpu);
			switch (r)
			{
				case EXCP_INTERRUPT:
                break;
                case EXCP_HLT:
                break;
                case EXCP_DEBUG:
                cpu_handle_guest_debug(cpu);
                runstate_set(RUN_STATE_DEBUG);
                vm_state_notify(0,RUN_STATE_DEBUG);
                break;
				case EXCP_HALTED:
                break;
				case EXCP_YIELD:
                break;
				case EXCP_ATOMIC:
                cpu_exec_step_atomic(cpu);
                break;
                default:
                exit(0);
                break;
			}
		} else if(debug)
        {
            main_loop_wait(true);
        }
	}
    cpu->exit_request = false;
    return r;
}


static void tcg_cpu_init_cflags(CPUState *cpu, bool parallel)
{
    uint32_t cflags = cpu->cluster_index << CF_CLUSTER_SHIFT;
    cflags |= parallel ? CF_PARALLEL : 0;
    cflags |= icount_enabled() ? CF_USE_ICOUNT : 0;
    cpu->tcg_cflags = cflags;
}

void xx_start_vcpu_thread(CPUState *cpu)
{
    tcg_cpu_init_cflags(cpu, false);
    static QemuCond *single_tcg_halt_cond = 0;
    static QemuThread *thread_self = 0;
    
    if(thread_self == 0)
        thread_self = g_malloc0(sizeof(QemuThread));
    if(single_tcg_halt_cond == 0)
        single_tcg_halt_cond = g_malloc0(sizeof(QemuCond));
    qemu_thread_get_self(thread_self);
    qemu_cond_init(single_tcg_halt_cond);
    cpu->thread = thread_self;
    cpu->halt_cond = single_tcg_halt_cond;
    //cpu->thread_id = first_cpu->thread_id;
    cpu->can_do_io = 1;
    cpu->created = true;
}


void xx_icount_handle_interrupt(CPUState *cpu, int mask)
{
    cpu->interrupt_request |= mask;
    qatomic_set(&cpu->icount_decr_ptr->u16.high, -1);
}
void xx_kick_vcpu_thread(CPUState *unused)
{
}
int64_t xx_icount_get(void)
{
	return 0;
}


static int xx_init_machine(MachineState *ms)
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

static void xx_accel_class_init(ObjectClass *oc, void *data)
{
    AccelClass *ac = ACCEL_CLASS(oc);
    ac->name = "xx";
    ac->init_machine = xx_init_machine;
    ac->allowed = &tcg_allowed;
}

static void xx_accel_ops_init(AccelOpsClass *ops)
{
    ops->create_vcpu_thread = xx_start_vcpu_thread;
    ops->kick_vcpu_thread = xx_kick_vcpu_thread;
    ops->handle_interrupt = xx_icount_handle_interrupt;
    ops->get_virtual_clock = xx_icount_get;
    ops->get_elapsed_ticks = xx_icount_get;

    ops->supports_guest_debug = tcg_supports_guest_debug;
    ops->insert_breakpoint = tcg_insert_breakpoint;
    ops->remove_breakpoint = tcg_remove_breakpoint;
    ops->remove_all_breakpoints = tcg_remove_all_breakpoints;
}

static void xx_accel_ops_class_init(ObjectClass *oc, void *data)
{
    AccelOpsClass *ops = ACCEL_OPS_CLASS(oc);
    ops->ops_init = xx_accel_ops_init;
}

static const TypeInfo xx_accel_type = {
    .name = ACCEL_CLASS_NAME("xx"),
    .parent = TYPE_ACCEL,
    .class_init = xx_accel_class_init,
};

static const TypeInfo xx_accel_ops_type = {
    .name = ACCEL_OPS_NAME("xx"),
    .parent = TYPE_ACCEL_OPS,
    .class_init = xx_accel_ops_class_init,
    .abstract = true,
};


static void xx_type_init(void)
{
    type_register_static(&xx_accel_type);
}
static void xx_accel_ops_register_types(void)
{
    type_register_static(&xx_accel_ops_type);
}


type_init(xx_accel_ops_register_types);
type_init(xx_type_init);
