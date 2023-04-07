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
enum XX_CPU_TYPE 
{
    X86,
    ARM
};
typedef bool (*exec_bbl_cb)(uint64_t pc,uint32_t id); 
exec_bbl_cb exec_bbl_func;

typedef void (*exec_ins_icmp_cb)(uint64_t val1,uint64_t val2, int used_bits);
exec_ins_icmp_cb exec_ins_icmp_func;


struct DirtyBitmapSnapshot {
    ram_addr_t start;
    ram_addr_t end;
    unsigned long dirty[];
};
bool tcg_supports_guest_debug(void);
void tcg_remove_all_breakpoints(CPUState *cpu);
int tcg_remove_breakpoint(CPUState *cs, int type, hwaddr addr, hwaddr len);
int tcg_insert_breakpoint(CPUState *cs, int type, hwaddr addr, hwaddr len);
int tcg_gdbstub_supported_sstep_flags(void);

extern bool tcg_allowed;

enum XX_CPU_TYPE xx_cpu_type;
enum XX_CPU_TYPE get_xx_cpu_type(){ return xx_cpu_type; }
void set_xx_cpu_type(enum XX_CPU_TYPE type) { xx_cpu_type = type; }



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
    MemoryRegion *mr;
};


#define XX_MEM_REGIONS_MAX 256
struct XX_RAMRegion xx_ram_regions[XX_MEM_REGIONS_MAX];
int xx_num_ram_regions;
struct XX_MMIORegion xx_mmio_regions[XX_MEM_REGIONS_MAX];
int xx_num_mmio_regions;
struct XX_ROMRegion xx_rom_regions[XX_MEM_REGIONS_MAX];
int xx_num_rom_regions;



MemTxResult xx_ram_rw(hwaddr addr,hwaddr len,void *buf, bool is_write)
{
    if (is_write) {
        return address_space_write(&address_space_memory, addr, MEMTXATTRS_UNSPECIFIED, buf, len);
    } else {
        return address_space_read_full(&address_space_memory, addr, MEMTXATTRS_UNSPECIFIED, buf, len);
    }
}
MemTxResult xx_rom_write(hwaddr addr,void *buf, hwaddr len)
{
    address_space_write_rom(&address_space_memory,addr,MEMTXATTRS_UNSPECIFIED,buf,len);
}

static bool check_mem_overlap(hwaddr start, hwaddr size)
{
    int i;
    hwaddr end = start + size;
    for(i=0; i < xx_num_ram_regions;i++)
    {
        if(
            !(start >= xx_ram_regions[i].start + xx_ram_regions[i].size || end <= xx_ram_regions[i].start)
        )
        return true;
    }
    for(i=0; i < xx_num_mmio_regions;i++)
    {
        if(
            !(start >= xx_mmio_regions[i].start + xx_mmio_regions[i].size || end <= xx_mmio_regions[i].start)
        )
        return true;
    }
    return false;
}
static bool check_mem_addr_and_size(hwaddr start, hwaddr size)
{
    hwaddr page_size = TARGET_PAGE_BITS == 0 ? 4 << 10 : 1 << TARGET_PAGE_BITS;
    if(start & (page_size -1) != 0 || size & (page_size - 1) != 0)
    {
        return false;
    }
    return true;
}
static MemoryRegion *find_mr_by_addr(hwaddr start, hwaddr size)
{
    MemoryRegion *mr = NULL;
    int i;
    for(i=0; i < xx_num_ram_regions;i++)
    {
        if(start >= xx_ram_regions[i].start && start + size <= xx_ram_regions[i].start + xx_ram_regions[i].size)
        {
            mr = xx_ram_regions[i].mr;
        }
    }
    for(i=0; i < xx_num_mmio_regions;i++)
    {
        if(start >= xx_mmio_regions[i].start && start + size <= xx_mmio_regions[i].start + xx_mmio_regions[i].size)
        {
            mr = xx_mmio_regions[i].mr;
        }
    }
    return mr;
}

void xx_add_ram_regions(char *name,hwaddr start, hwaddr size, bool readonly)
{
    if(xx_num_ram_regions >= XX_MEM_REGIONS_MAX)
        return;
    if(check_mem_overlap(start,size))
        return;
    if(!check_mem_addr_and_size(start,size))
        return;
    xx_ram_regions[xx_num_ram_regions].name = strdup(name);
    xx_ram_regions[xx_num_ram_regions].start = start;
    xx_ram_regions[xx_num_ram_regions].size = size;
    xx_ram_regions[xx_num_ram_regions].readonly = readonly;
    xx_num_ram_regions++;

}
void xx_add_rom_region(char *name,hwaddr start, hwaddr size)
{
    if(xx_num_rom_regions >= XX_MEM_REGIONS_MAX)
	    return;
    if(check_mem_overlap(start,size))
	    return;
    if(!check_mem_addr_and_size(start,size))
	    return;
    xx_rom_regions[xx_num_rom_regions].name = strdup(name);
    xx_rom_regions[xx_num_rom_regions].start = start;
    xx_rom_regions[xx_num_rom_regions].size = size;
    xx_num_rom_regions++;
}
void xx_add_mmio_regions(char *name, hwaddr start, hwaddr size, void *read_cb, void *write_cb)
{
    if(xx_num_mmio_regions >= XX_MEM_REGIONS_MAX)
        return;
    if(check_mem_overlap(start,size))
        return;
    if(!check_mem_addr_and_size(start,size))
        return;
    xx_mmio_regions[xx_num_mmio_regions].name = strdup(name);
    xx_mmio_regions[xx_num_mmio_regions].start = start;
    xx_mmio_regions[xx_num_mmio_regions].size = size;
    xx_mmio_regions[xx_num_mmio_regions].read_cb = read_cb;
    xx_mmio_regions[xx_num_mmio_regions].write_cb = write_cb;
    xx_num_mmio_regions++;
}

RAMBlock *qemu_get_ram_block(ram_addr_t addr);
void xx_clear_dirty_mem(ram_addr_t addr, ram_addr_t size)
{
    MemoryRegion *mr = find_mr_by_addr(addr,size);
    tlb_reset_dirty_range_all(addr, size);
    memory_region_clear_dirty_bitmap(mr, addr - mr->addr, size);
    //printf("clear dirty pages %p-%p\n",addr,addr+size);
}
int xx_target_pagesize()
{
    return 1 << TARGET_PAGE_BITS;
}
void xx_get_dirty_pages(hwaddr addr,hwaddr size, unsigned long dirty[])
{
    int num_page_in_byte = 0;
    hwaddr page_size = TARGET_PAGE_BITS == 0 ? 4 << 10 : 1 << TARGET_PAGE_BITS;
    if(!check_mem_addr_and_size(addr,size))
        return;
    MemoryRegion *mr = find_mr_by_addr(addr,size);
    if(!mr)
        return;
    DirtyBitmapSnapshot * snap = memory_region_snapshot_and_clear_dirty(mr,addr - mr->addr , size, DIRTY_MEMORY_VGA);
    //num_page_in_byte = ((size / page_size) / 8) + (((size / page_size) % 8) ? 1 : 0) ;
    num_page_in_byte = ((size / page_size) / 8) + 1;

    memcpy(dirty,snap->dirty,num_page_in_byte);
    g_free(snap);
    //printf("get dirty pages %p-%p totally :%d byte\n",addr,addr+size,num_page_in_byte);
}


void xx_init_mem(MachineState *machine)
{

                
    MemoryRegion *ram_space = get_system_memory();
    MemoryRegion *mmio_space = get_system_io();
    int i;
    for(i=0; i < xx_num_ram_regions;i++)
    {
        MemoryRegion *mr = g_new0(MemoryRegion, 1);
        memory_region_init_ram(mr,NULL,xx_ram_regions[i].name,xx_ram_regions[i].size,0);
        memory_region_set_log(mr, true, DIRTY_MEMORY_VGA);
        memory_region_reset_dirty(mr, 0, xx_ram_regions[i].size, DIRTY_MEMORY_VGA);
	memory_region_set_readonly(mr, xx_ram_regions[i].readonly);
        memory_region_add_subregion(ram_space,xx_ram_regions[i].start,mr);
        xx_ram_regions[i].mr = mr;
        printf("add ram %x-%x %s readonly:%d\n",xx_ram_regions[i].start, xx_ram_regions[i].start+xx_ram_regions[i].size, xx_ram_regions[i].name,xx_ram_regions[i].readonly);
    }
    for(i = 0 ; i < xx_num_rom_regions ; i++)
    {
        MemoryRegion *mr = g_new0(MemoryRegion, 1);
	memory_region_init_rom(mr,NULL,xx_rom_regions[i].name,xx_rom_regions[i].size,0);
        memory_region_add_subregion(ram_space,xx_rom_regions[i].start,mr);
	xx_rom_regions[i].mr = mr;
	printf("add rom %x-%x %s\n",xx_rom_regions[i].start, xx_rom_regions[i].start+xx_rom_regions[i].size, xx_rom_regions[i].name);
    }
    for(i=0; i < xx_num_mmio_regions;i++)
    {
        struct MemoryRegionOps *ops = g_new0(MemoryRegionOps, 1);
        ops->read = xx_mmio_regions[i].read_cb;
        ops->write = xx_mmio_regions[i].write_cb;
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
        memory_region_init_io(mr,NULL,ops,NULL,xx_mmio_regions[i].name,xx_mmio_regions[i].size);
	    //memory_region_add_subregion(mmio_space,xx_mmio_regions[i].start,mr);
        // memory_region_set_log(mr, true, DIRTY_MEMORY_VGA);
        // memory_region_reset_dirty(mr, 0, xx_ram_regions[i].size, DIRTY_MEMORY_VGA);
        memory_region_add_subregion(ram_space,xx_mmio_regions[i].start,mr);
        xx_mmio_regions[i].mr = mr;

        printf("add mmio %x-%x %s\n",xx_mmio_regions[i].start, xx_mmio_regions[i].start+xx_mmio_regions[i].size, xx_mmio_regions[i].name);
    }
}

void xx_register_exec_bbl_hook(exec_bbl_cb cb)
{
    exec_bbl_func = cb;
}
void xx_register_exec_ins_icmp_hook(exec_ins_icmp_cb cb)
{
    exec_ins_icmp_func = cb;
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
		CPUClass *cc = CPU_GET_CLASS(cpu);

        init = true;
    }
    //qemu_mutex_unlock_iothread();
    if(!cpu->stop && !cpu->exit_request)
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
    //cpu->thread_id = first_cpu->thread_id;
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
    ac->gdbstub_supported_sstep_flags = tcg_gdbstub_supported_sstep_flags;
}

static void xx_accel_ops_init(AccelOpsClass *ops)
{
    ops->create_vcpu_thread = xx_start_vcpu_thread;
    ops->kick_vcpu_thread = xx_kick_vcpu_thread;
    ops->handle_interrupt = xx_icount_handle_interrupt;
    //ops->get_virtual_clock = xx_icount_get;
    //ops->get_elapsed_ticks = xx_icount_get;

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
