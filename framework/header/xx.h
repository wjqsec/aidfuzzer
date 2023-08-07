#ifndef XX_INCLUDED

#define XX_INCLUDED
#include <stdint.h>
#include <glib.h>
typedef uint64_t hwaddr;
typedef uint32_t MemTxResult;

enum XX_CPU_TYPE 
{
    X86,
    ARM_CORTEX_M
};


struct XXSimulator
{
    enum XX_CPU_TYPE cpu_type;
    bool enable_gdb_dbg;
};

#define EXCP_INTERRUPT 	0x10000 /* async interruption */
#define EXCP_HLT        0x10001 /* hlt instruction reached */
#define EXCP_DEBUG      0x10002 /* cpu stopped after a breakpoint or singlestep */
#define EXCP_HALTED     0x10003 /* cpu is halted (waiting for external event) */
#define EXCP_YIELD      0x10004 /* cpu wants to yield timeslice to another */
#define EXCP_ATOMIC     0x10005 /* stop-the-world and emulate atomic */

#define BP_MEM_READ           0x01
#define BP_MEM_WRITE          0x02
#define BP_MEM_ACCESS         (BP_MEM_READ | BP_MEM_WRITE)
#define BP_CALLBACK_ONLY_NO_STOP 0X100
//----------------x86
struct X86_CPU_STATE
{
    uint64_t  regs[8];  //EAX EBX ECX EDX ESI EDI EBP ESP
    uint64_t  eip;                 //EIP
};

typedef void (*x86_cpu_do_interrupt_cb)(void); 
typedef void (*x86_cpu_exec_interrupt_cb)(void); 
typedef void (*x86_cpu_do_unaligned_access_cb)(void); 

void xx_get_x86_cpu_state(struct X86_CPU_STATE *state);
void xx_set_x86_cpu_state(struct X86_CPU_STATE *state);
void xx_register_x86_cpu_do_interrupt_hook(x86_cpu_do_interrupt_cb cb);
void xx_register_x86_cpu_exec_interrupt_hook_ptr(x86_cpu_exec_interrupt_cb cb);
void xx_register_x86_cpu_do_unaligned_access_hook_ptr(x86_cpu_do_unaligned_access_cb cb);
void *xx_save_x86_ctx_state(void);
void xx_restore_x86_ctx_state(void* state);
void xx_delete_x86_ctx_state(void* state);


#define get_x86_cpu_state xx_get_x86_cpu_state
#define set_x86_cpu_state xx_set_x86_cpu_state
#define register_x86_cpu_do_interrupt_hook xx_register_x86_cpu_do_interrupt_hook
#define register_x86_cpu_exec_interrupt_hook_ptr xx_register_x86_cpu_exec_interrupt_hook_ptr
#define register_x86_cpu_do_unaligned_access_hook_ptr xx_register_x86_cpu_do_unaligned_access_hook_ptr
#define save_x86_ctx_state xx_save_x86_ctx_state
#define restore_x86_ctx_state xx_restore_x86_ctx_state
#define delete_x86_ctx_state xx_delete_x86_ctx_state
//===================arm
#define EXCP_UDEF            1   /* undefined instruction */
#define EXCP_SWI             2   /* software interrupt */
#define EXCP_PREFETCH_ABORT  3
#define EXCP_DATA_ABORT      4
#define EXCP_IRQ             5
#define EXCP_FIQ             6
#define EXCP_BKPT            7
#define EXCP_EXCEPTION_EXIT  8   /* Return from v7M exception.  */
#define EXCP_KERNEL_TRAP     9   /* Jumped to kernel code page.  */
#define EXCP_HVC            11   /* HyperVisor Call */
#define EXCP_HYP_TRAP       12
#define EXCP_SMC            13   /* Secure Monitor Call */
#define EXCP_VIRQ           14
#define EXCP_VFIQ           15
#define EXCP_SEMIHOST       16   /* semihosting call */
#define EXCP_NOCP           17   /* v7M NOCP UsageFault */
#define EXCP_INVSTATE       18   /* v7M INVSTATE UsageFault */
#define EXCP_STKOF          19   /* v8M STKOF UsageFault */
#define EXCP_LAZYFP         20   /* v7M fault during lazy FP stacking */
#define EXCP_LSERR          21   /* v8M LSERR SecureFault */
#define EXCP_UNALIGNED      22   /* v7M UNALIGNED UsageFault */
#define EXCP_DIVBYZERO      23   /* v7M DIVBYZERO UsageFault */

#define ARMV7M_EXCP_RESET   1
#define ARMV7M_EXCP_NMI     2
#define ARMV7M_EXCP_HARD    3
#define ARMV7M_EXCP_MEM     4
#define ARMV7M_EXCP_BUS     5
#define ARMV7M_EXCP_USAGE   6
#define ARMV7M_EXCP_SECURE  7
#define ARMV7M_EXCP_SVC     11
#define ARMV7M_EXCP_DEBUG   12
#define ARMV7M_EXCP_PENDSV  14
#define ARMV7M_EXCP_SYSTICK 15
struct ARM_CPU_STATE
{
    uint32_t regs[16]; 
    uint64_t xregs[32];
    uint32_t xpsr;
};


typedef bool (*do_arm_interrupt_cb)(int32_t exec_index);
typedef void (*exec_nvic_cb)(int irq);
typedef void (*enable_nvic_cb)(int irq);
void xx_get_arm_cpu_state(struct ARM_CPU_STATE *state);
void xx_set_arm_cpu_state(struct ARM_CPU_STATE *state);
void *xx_save_arm_ctx_state(void);
void xx_restore_arm_ctx_state(void* state);
void xx_delete_arm_ctx_state(void* state);
bool xx_insert_nvic_intc(int irq);
GArray* xx_get_enabled_nvic_irq(void);
uint32_t* xx_get_enabled_nvic_irq2(uint16_t **irqs);
void xx_reset_arm_reg(void);
void xx_register_arm_do_interrupt_hook(do_arm_interrupt_cb cb);
void xx_set_armv7_vecbase(hwaddr addr);
hwaddr xx_get_arm_precise_pc(void);
void xx_register_exec_nvic_hook(exec_nvic_cb cb);
void xx_register_enable_nvic_hook(enable_nvic_cb cb);
bool xx_get_arm_v7m_is_handler_mode(void);


#define get_arm_cpu_state xx_get_arm_cpu_state
#define set_arm_cpu_state xx_set_arm_cpu_state
#define save_arm_ctx_state xx_save_arm_ctx_state
#define restore_arm_ctx_state xx_restore_arm_ctx_state
#define delete_arm_ctx_state xx_delete_arm_ctx_state
#define insert_nvic_intc xx_insert_nvic_intc
#define get_enabled_nvic_irq xx_get_enabled_nvic_irq
#define get_enabled_nvic_irq2 xx_get_enabled_nvic_irq2
#define reset_arm_reg xx_reset_arm_reg
#define register_arm_do_interrupt_hook xx_register_arm_do_interrupt_hook
#define set_armv7_vecbase xx_set_armv7_vecbase
#define get_arm_precise_pc xx_get_arm_precise_pc
#define register_exec_nvic_hook xx_register_exec_nvic_hook
#define register_enable_nvic_hook xx_register_enable_nvic_hook
#define get_arm_v7m_is_handler_mode xx_get_arm_v7m_is_handler_mode

//===================common




typedef uint64_t (*mmio_read_cb)(void *opaque,hwaddr addr_offset,unsigned size);
typedef void (*mmio_write_cb)(void *opaque,hwaddr addr_offset,uint64_t data,unsigned size);

typedef void (*pre_thread_exec_cb)(void); 
typedef bool (*exec_bbl_cb)(uint64_t pc,uint32_t id,int64_t bbl);
typedef void (*exec_func_cb)(uint64_t pc,uint64_t *return_val);

typedef void (*exec_ins_icmp_cb)(uint64_t pc,uint64_t val1,uint64_t val2, int used_bits, int immediate_index); 
typedef void (*post_thread_exec_cb)(int exec_ret);
typedef void (*nostop_watchpoint_cb)(hwaddr vaddr,hwaddr len,hwaddr hitaddr,void *data);
 
struct BBL_Hook
{
    hwaddr addr;
    exec_bbl_cb cb;
};
struct Func_Hook
{
    hwaddr addr;
    exec_func_cb cb;
};


struct XXSimulator *create_simulator(enum XX_CPU_TYPE cpu_type,bool dbg);     
void init_simulator(struct XXSimulator * s);
void exec_simulator(struct XXSimulator *s);
void check_nostop_watchpoint(hwaddr addr);

enum XX_CPU_TYPE get_xx_cpu_type(void);
void set_xx_cpu_type(enum XX_CPU_TYPE type);
int xx_thread_loop(bool debug);
void xx_register_pre_thread_exec_hook(pre_thread_exec_cb cb);
void xx_register_exec_bbl_hook(exec_bbl_cb cb);
void xx_register_exec_specific_bbl_hook(hwaddr addr,exec_bbl_cb cb);
void xx_register_exec_func_hook(hwaddr addr,exec_func_cb cb);

void xx_register_exec_ins_icmp_hook(exec_ins_icmp_cb cb);
void xx_register_post_thread_exec_hook(post_thread_exec_cb cb);
MemTxResult xx_write_ram(hwaddr addr, hwaddr size, void *buf);  //will make the page dirty
MemTxResult xx_read_ram(hwaddr addr, hwaddr size, void *buf);
MemTxResult xx_rom_write(hwaddr addr,void *buf, hwaddr len);
void xx_add_ram_region(char *name,hwaddr start, hwaddr size, bool readonly);
void xx_add_rom_region(char *name,hwaddr start, hwaddr size);
void xx_add_mmio_region(char *name, hwaddr start, hwaddr size, mmio_read_cb mmio_read_cb, mmio_write_cb mmio_write_cb,void * opaque);
void xx_load_file_ram(char *filename,hwaddr addr, int file_offset, int size);
void xx_load_file_rom(char *filename,hwaddr addr, int file_offset, int size);
int xx_target_pagesize(void);
void xx_clear_dirty_mem(hwaddr start, hwaddr size);
void xx_get_dirty_pages(hwaddr addr,hwaddr size, unsigned long dirty[]);
void *xx_insert_nostop_watchpoint(hwaddr addr, hwaddr len, int flag, nostop_watchpoint_cb cb, void *data);
void xx_delete_nostop_watchpoint(void *watchpoint);


#define thread_loop xx_thread_loop
#define register_pre_thread_exec_hook xx_register_pre_thread_exec_hook
#define register_exec_bbl_hook xx_register_exec_bbl_hook
#define register_exec_specific_bbl_hook xx_register_exec_specific_bbl_hook
#define register_exec_func_hook xx_register_exec_func_hook
#define register_exec_ins_icmp_hook xx_register_exec_ins_icmp_hook
#define register_post_thread_exec_hook xx_register_post_thread_exec_hook
#define write_ram xx_write_ram
#define read_ram xx_read_ram
#define add_ram_region xx_add_ram_region
#define add_rom_region xx_add_rom_region
#define add_mmio_region xx_add_mmio_region
#define load_file_ram xx_load_file_ram
#define load_file_rom xx_load_file_rom
#define target_pagesize xx_target_pagesize
#define clear_dirty_mem xx_clear_dirty_mem
#define get_dirty_pages xx_get_dirty_pages
#define insert_nostop_watchpoint xx_insert_nostop_watchpoint
#define delete_nostop_watchpoint xx_delete_nostop_watchpoint

#endif

