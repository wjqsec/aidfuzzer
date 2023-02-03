#include "qemu/osdep.h"
#include "sysemu/tcg.h"
#include "sysemu/replay.h"
#include "sysemu/cpu-timers.h"
#include "qemu/main-loop.h"
#include "qemu/guest-random.h"
#include "exec/exec-all.h"
#include "exec/hwaddr.h"
#include "exec/gdbstub.h"

static void tcg_cpu_init_cflags(CPUState *cpu, bool parallel)
{
    uint32_t cflags = cpu->cluster_index << CF_CLUSTER_SHIFT;
    cflags |= parallel ? CF_PARALLEL : 0;
    cflags |= icount_enabled() ? CF_USE_ICOUNT : 0;
    cpu->tcg_cflags = cflags;
}

void xxfuzzer_start_vcpu_thread(CPUState *cpu)
{
    tcg_cpu_init_cflags(cpu, false);
    static QemuCond *single_tcg_halt_cond;
    static QemuThread *single_tcg_cpu_thread;
    cpu->thread = single_tcg_cpu_thread;
    cpu->halt_cond = single_tcg_halt_cond;
    cpu->thread_id = first_cpu->thread_id;
    cpu->can_do_io = 1;
    //cpu->created = true;
}
void xxfuzzer_icount_handle_interrupt(CPUState *cpu, int mask)
{
    
}
void xxfuzzer_kick_vcpu_thread(CPUState *unused)
{
}
int64_t xxfuzzer_icount_get(void)
{
	return 0;
}
