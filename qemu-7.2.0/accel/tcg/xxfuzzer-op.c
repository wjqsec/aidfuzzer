#include "qemu/osdep.h"
#include "sysemu/tcg.h"
#include "sysemu/replay.h"
#include "sysemu/cpu-timers.h"
#include "qemu/main-loop.h"
#include "qemu/guest-random.h"
#include "exec/exec-all.h"
#include "exec/hwaddr.h"
#include "exec/gdbstub.h"

#include "qemu/osdep.h"
#include "sysemu/tcg.h"
#include "sysemu/replay.h"
#include "sysemu/cpu-timers.h"
#include "qemu/main-loop.h"
#include "qemu/notify.h"
#include "qemu/guest-random.h"
#include "exec/exec-all.h"



static void tcg_cpu_init_cflags(CPUState *cpu, bool parallel)
{
    uint32_t cflags = cpu->cluster_index << CF_CLUSTER_SHIFT;
    cflags |= parallel ? CF_PARALLEL : 0;
    cflags |= icount_enabled() ? CF_USE_ICOUNT : 0;
    cpu->tcg_cflags = cflags;
}


void xxfuzzer_thread_loop(bool debug)
{
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
    qemu_mutex_unlock_iothread();
    while(!cpu->stop && !cpu->exit_request)
    {
        if(!cpu_work_list_empty(cpu))
	    process_queued_cpu_work(cpu);
	if(debug)
	    main_loop_wait(false);
	if(cpu_can_run(cpu))
	{
	    cpu_exec_start(cpu);
	    CPUClass *cc = CPU_GET_CLASS(cpu);
	    int r = cpu_exec(cpu);
	    cpu_exec_end(cpu);
	    switch (r)
	    {
		    case EXCP_INTERRUPT:
			    //printf("ex interrupt\n");
			    break;
	            case EXCP_HLT:
			    //printf("hlt\n");
			    break;
	            case EXCP_DEBUG:
			    cpu_handle_guest_debug(cpu);
			    runstate_set(RUN_STATE_DEBUG);
			    vm_state_notify(0,RUN_STATE_DEBUG);
			    //printf("debug\n");
                            break;
		    case EXCP_HALTED:
			    //printf("halted\n");
                            break;
		    case EXCP_YIELD:
			    //printf("yield\n");
                            break;
		    case EXCP_ATOMIC:
			    cpu_exec_step_atomic(cpu);
			    //printf("atomic\n");
                            break;
	            default:
			    exit(0);
			    break;

	    }
	    
	}
	else if(debug)
	{
	    main_loop_wait(false);
	}
	else
	{

	}
    }
    cpu->exit_request = false;
    
}

void xxfuzzer_start_vcpu_thread(CPUState *cpu)
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
    //xxfuzzer_vcpu_thread(cpu);
}


void xxfuzzer_icount_handle_interrupt(CPUState *cpu, int mask)
{
    cpu->interrupt_request |= mask;
    qatomic_set(&cpu->icount_decr_ptr->u16.high, -1);
}
void xxfuzzer_kick_vcpu_thread(CPUState *unused)
{
}
int64_t xxfuzzer_icount_get(void)
{
	return 0;
}
