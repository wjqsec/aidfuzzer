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
#include "exec/cpu-all.h"
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
#include "hw/core/tcg-cpu-ops.h"
#include <sys/resource.h>
#include <sys/shm.h>
#include <stdio.h>
#include <unistd.h>
#include "fuzzer.h"
#include "xx.h"




NOSTOP_WATCHPOINT **nostop_watchpoints;
uint8_t *mem_has_watchpoints;

mem_access_cb mem_access_log_func;
translate_bbl_cb translate_bbl_func;
exec_bbl_cb exec_bbl_func;

GArray* specific_bbl_hooks;
GArray* func_hooks;
int64_t bbl_counts;




struct DirtyBitmapSnapshot {
    ram_addr_t start;
    ram_addr_t end;
    unsigned long dirty[];
};



void page_init(void);
void tb_htable_init(void);
void vm_state_notify(bool running, RunState state);
void runstate_set(RunState new_state);
bool tcg_supports_guest_debug(void);
void tcg_remove_all_breakpoints(CPUState *cpu);
int tcg_remove_breakpoint(CPUState *cs, int type, hwaddr addr, hwaddr len);
int tcg_insert_breakpoint(CPUState *cs, int type, hwaddr addr, hwaddr len);
int tcg_gdbstub_supported_sstep_flags(void);

extern bool tcg_allowed;


struct XX_RAMRegion
{
    char *name;
    hwaddr start;
    hwaddr size;
    MemoryRegion *mr;
    bool readonly;
};

struct XX_ROMRegion
{
    char *name;
    hwaddr start;
    hwaddr size;
    MemoryRegion *mr;
};

struct XX_MMIORegion
{
    char *name;
    hwaddr start;
    hwaddr size;
    void *read_cb;
    void *write_cb;
    void *opaque;
    MemoryRegion *mr;
};



struct XX_RAMRegion xx_ram_regions[MAX_NUM_MEM_REGION];
int xx_num_ram_regions;
struct XX_MMIORegion xx_mmio_regions[MAX_NUM_MEM_REGION];
int xx_num_mmio_regions;
struct XX_ROMRegion xx_rom_regions[MAX_NUM_MEM_REGION];
int xx_num_rom_regions;



int target_pagesize(void)
{
    return 1 << TARGET_PAGE_BITS;
}


void write_ram(hw_addr addr, hw_addr size, void *buf)
{
    address_space_write(&address_space_memory, addr, MEMTXATTRS_UNSPECIFIED_NO_SET_INVALID, buf, size);
}
void read_ram(hw_addr addr, hw_addr size, void *buf)
{
    address_space_read_full(&address_space_memory, addr, MEMTXATTRS_UNSPECIFIED_NO_SET_INVALID, buf, size);
}

void rom_write(hw_addr addr, hw_addr len, void *buf)
{
    address_space_write_rom(&address_space_memory,addr,MEMTXATTRS_UNSPECIFIED,buf,len);
}

static MemoryRegion *find_mr_by_addr(hw_addr start)
{
    MemoryRegion *mr = NULL;
    int i;
    for(i=0; i < xx_num_ram_regions;i++)
    {
        if(start >= xx_ram_regions[i].start && start < xx_ram_regions[i].start + xx_ram_regions[i].size)
        {
            mr = xx_ram_regions[i].mr;
            return mr;
        }
    }
    for(i=0; i < xx_num_rom_regions;i++)
    {   
        if(start >= xx_rom_regions[i].start && start < xx_rom_regions[i].start + xx_rom_regions[i].size)
        {   
            mr = xx_rom_regions[i].mr;
            return mr;
        }
    }
    for(i=0; i < xx_num_mmio_regions;i++)
    {
        if(start >= xx_mmio_regions[i].start && start < xx_mmio_regions[i].start + xx_mmio_regions[i].size)
        {
            mr = xx_mmio_regions[i].mr;
            return mr;
        }
    }
    return NULL;
}

void add_ram_region(char *name,hw_addr start, hw_addr size, bool readonly)
{
    if(xx_num_ram_regions >= MAX_NUM_MEM_REGION)
        return;
    start = ROUND_DOWN(start,target_pagesize());
    size = ROUND_UP(size, target_pagesize());
    MemoryRegion *ram_space = get_system_memory();
    //MemoryRegion *mmio_space = get_system_io();
    

    
    MemoryRegion *mr = g_new0(MemoryRegion, 1);
    memory_region_init_ram(mr,NULL,name,size,0);
    memory_region_set_log(mr, true, DIRTY_MEMORY_VGA);
    memory_region_reset_dirty(mr, 0, size, DIRTY_MEMORY_VGA);
    memory_region_set_readonly(mr, readonly);



    MemoryRegion *old = find_mr_by_addr(start);
    if(old)
	  memory_region_add_subregion_overlap(ram_space,start,mr,old->priority+1);
    else
        memory_region_add_subregion(ram_space,start,mr);
        //memory_region_del_subregion(ram_space,old);

    xx_ram_regions[xx_num_ram_regions].name = strdup(name);
    xx_ram_regions[xx_num_ram_regions].start = start;
    xx_ram_regions[xx_num_ram_regions].size = size;
    xx_ram_regions[xx_num_ram_regions].readonly = readonly;
    xx_ram_regions[xx_num_ram_regions].mr = mr;
    xx_num_ram_regions++;
    printf("add ram %lx-%lx %s readonly:%d\n",start, start+size,name,readonly);
}
void add_rom_region(char *name,hw_addr start, hw_addr size)
{
    if(xx_num_rom_regions >= MAX_NUM_MEM_REGION)
	    return;
    start = ROUND_DOWN(start,target_pagesize());
    size = ROUND_UP(size, target_pagesize());
    MemoryRegion *ram_space = get_system_memory();
    //MemoryRegion *mmio_space = get_system_io();
    

    MemoryRegion *mr = g_new0(MemoryRegion, 1);
    memory_region_init_rom(mr,NULL,name,size,0);

    MemoryRegion *old = find_mr_by_addr(start);
    if(old)
          memory_region_add_subregion_overlap(ram_space,start,mr,old->priority+1);
    else
          memory_region_add_subregion(ram_space,start,mr);



    xx_rom_regions[xx_num_rom_regions].name = strdup(name);
    xx_rom_regions[xx_num_rom_regions].start = start;
    xx_rom_regions[xx_num_rom_regions].size = size;
    xx_rom_regions[xx_num_rom_regions].mr = mr;
    xx_num_rom_regions++;
    printf("add rom %lx-%lx %s\n",start, start+size,name);
}
void add_mmio_region(char *name, hw_addr start, hw_addr size, mmio_read_cb read_cb, mmio_write_cb write_cb,void *opaque)
{
    if(xx_num_mmio_regions >= MAX_NUM_MEM_REGION)
        return;
    start = ROUND_DOWN(start,target_pagesize());
    size = ROUND_UP(size, target_pagesize());

    MemoryRegion *ram_space = get_system_memory();
    //MemoryRegion *mmio_space = get_system_io();

    struct MemoryRegionOps *ops = g_new0(MemoryRegionOps, 1);
    ops->read = read_cb;
    ops->write = write_cb;
    ops->read_with_attrs = 0;
    ops->write_with_attrs = 0;
    ops->endianness = DEVICE_NATIVE_ENDIAN;
    ops->valid.min_access_size = 1;
    ops->valid.max_access_size = 8;
    ops->valid.unaligned = true;
    ops->valid.accepts = NULL;
    ops->impl.min_access_size = 1;
    ops->impl.max_access_size = 8;
    ops->impl.unaligned = true;
    MemoryRegion *mr = g_new0(MemoryRegion, 1);
    memory_region_init_io(mr,NULL,ops,opaque,name,size);
          
    
    MemoryRegion *old = find_mr_by_addr(start);
    if(old)
          memory_region_add_subregion_overlap(ram_space,start,mr,old->priority+1);
    else
          memory_region_add_subregion(ram_space,start,mr);

    xx_mmio_regions[xx_num_mmio_regions].name = strdup(name);
    xx_mmio_regions[xx_num_mmio_regions].start = start;
    xx_mmio_regions[xx_num_mmio_regions].size = size;
    xx_mmio_regions[xx_num_mmio_regions].read_cb = read_cb;
    xx_mmio_regions[xx_num_mmio_regions].write_cb = write_cb;
    xx_mmio_regions[xx_num_mmio_regions].opaque = opaque;
    xx_mmio_regions[xx_num_mmio_regions].mr = mr;
    xx_num_mmio_regions++;
    printf("add mmio %lx-%lx %s\n",start, start+size,name);
}



void get_dirty_pages(hw_addr addr,hw_addr size, unsigned long dirty[])
{
    int num_page_in_byte = 0;

    MemoryRegion *mr = find_mr_by_addr(addr);
    if(!mr)
        return;
    DirtyBitmapSnapshot * snap = memory_region_snapshot_and_clear_dirty(mr,addr - mr->addr , size, DIRTY_MEMORY_VGA);
    num_page_in_byte = ((size / target_pagesize()) / 8) + 1;
    memcpy(dirty,snap->dirty,num_page_in_byte);
    g_free(snap);

}

void register_mem_access_log_hook(mem_access_cb cb)
{
    mem_access_log_func = cb;
}
void register_exec_bbl_hook(exec_bbl_cb cb)
{
    exec_bbl_func = cb;
}
void register_translate_bbl_hook(translate_bbl_cb cb)
{
    translate_bbl_func = cb;
}
void register_exec_specific_bbl_hook(hw_addr addr,exec_bbl_cb cb)
{
    BBL_Hook *hook = g_malloc0(sizeof(BBL_Hook));
    hook->addr = addr;
    hook->cb = cb;
    g_array_append_vals(specific_bbl_hooks,&hook,1);
}
void register_exec_func_hook(hw_addr addr,exec_func_cb cb)
{
    Func_Hook *hook = g_malloc0(sizeof(Func_Hook));
    hook->addr = addr;
    hook->cb = cb;
    g_array_append_vals(func_hooks,&hook,1);
}


NOSTOP_WATCHPOINT* insert_nostop_watchpoint(hw_addr addr, hw_addr len, qemu_plugin_mem_rw_ flag, nostop_watchpoint_cb cb,void *data)
{
    int i;
    NOSTOP_WATCHPOINT *point = g_malloc0(sizeof(NOSTOP_WATCHPOINT));
    point->addr = addr;
    point->len = len;
    point->flag = flag;
    point->cb = cb;
    point->data = data;
    
    uint32_t id = hash_32(addr) % NUM_WATCHPOINT;
    NOSTOP_WATCHPOINT ** ptr = nostop_watchpoints + id * NUM_WATCHPOINT_PER_SLOT;
    for(i = 0; i < NUM_WATCHPOINT_PER_SLOT ;i++)
    {
        if(ptr[i] == 0)
        {
            ptr[i] = point;
            mem_has_watchpoints[id]++;
            return point;
        }
    }
    g_free(point);
    return NULL;
}

void delete_nostop_watchpoint(NOSTOP_WATCHPOINT *watchpoint)
{
    int i;
    uint32_t id = hash_32(watchpoint->addr) % NUM_WATCHPOINT;
    NOSTOP_WATCHPOINT ** ptr = nostop_watchpoints + id * NUM_WATCHPOINT_PER_SLOT;
    for(i = 0; i < NUM_WATCHPOINT_PER_SLOT ;i++)
    {
        if(ptr[i] == watchpoint)
        {
            g_free(watchpoint);
            ptr[i] = 0;
            mem_has_watchpoints[id]--;
            break;
        }
    }
}

int thread_loop(bool debug)
{
    int r = 0;
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

        init = true;
    }

    //if(!cpu->stop && !cpu->exit_request)
    {
        if(!cpu_work_list_empty(cpu))
        {
            process_queued_cpu_work(cpu);
        }
	        
		if(debug)
        {
            main_loop_wait(false);
        }
			
		if(cpu_can_run(cpu))
		{
			cpu_exec_start(cpu);
			r = cpu_exec(cpu);
			cpu_exec_end(cpu);
			switch (r)
			{
				case EXCP_INTERRUPT:
                break;
                case EXCP_HLT:
                break;
                case EXCP_DEBUG:
                if(debug)
                {
                    cpu_handle_guest_debug(cpu);
                    runstate_set(RUN_STATE_DEBUG);
                    vm_state_notify(0,RUN_STATE_DEBUG);
                }
                else
                {
                  
                }
                
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
            main_loop_wait(false);
        }
    }
    cpu->exit_request = false;
    cpu->stop = false;
    cpu->halted = false;
    return r;
}


static void tcg_cpu_init_cflags(CPUState *cpu, bool parallel)
{
    uint32_t cflags = cpu->cluster_index << CF_CLUSTER_SHIFT;
    cflags |= parallel ? CF_PARALLEL : 0;
    cflags |= icount_enabled() ? CF_USE_ICOUNT : 0;
    cflags |= CF_SINGLE_STEP;
    cpu->tcg_cflags = cflags;
}

static void xx_start_vcpu_thread(CPUState *cpu)
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
    cpu->can_do_io = 1;
    cpu->created = true;

    
}


static void xx_icount_handle_interrupt(CPUState *cpu, int mask)
{
    cpu->interrupt_request |= mask;
    qatomic_set(&cpu->icount_decr_ptr->u16.high, -1);
}
static void xx_kick_vcpu_thread(CPUState *unused)
{
}
static int64_t xx_icount_get(void)
{
	return bbl_counts * MILISECONS_PER_BBL;
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
    ac->gdbstub_supported_sstep_flags = tcg_gdbstub_supported_sstep_flags;


    nostop_watchpoints = (NOSTOP_WATCHPOINT **)malloc(NUM_WATCHPOINT * sizeof(void*) * NUM_WATCHPOINT_PER_SLOT);
    memset(nostop_watchpoints,0,NUM_WATCHPOINT * sizeof(void*) * NUM_WATCHPOINT_PER_SLOT);
    mem_has_watchpoints = (uint8_t *)malloc(NUM_WATCHPOINT * sizeof(mem_has_watchpoints[0]));
    memset(mem_has_watchpoints,0,NUM_WATCHPOINT * sizeof(mem_has_watchpoints[0]));

    specific_bbl_hooks = g_array_new(false,false,sizeof(BBL_Hook *));
    func_hooks = g_array_new(false,false,sizeof(Func_Hook *));
    bbl_counts = 0;

    mem_access_log_func = 0;
    translate_bbl_func = 0;
    exec_bbl_func = 0;
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
