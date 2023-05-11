typedef uint64_t hwaddr;
typedef uint64_t regval;
typedef uint32_t MemTxResult;

enum XX_CPU_TYPE 
{
    X86,
    ARM
};


struct Simulator
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


//----------------x86
struct X86_CPU_STATE
{
    regval regs[8];  //EAX EBX ECX EDX ESI EDI EBP ESP
    regval eip;                 //EIP
};

typedef void (*x86_cpu_do_interrupt_cb)(); 
typedef void (*x86_cpu_exec_interrupt_cb)(); 
typedef void (*x86_cpu_do_unaligned_access_cb)(); 

void get_x86_cpu_state(struct X86_CPU_STATE *state);
void set_x86_cpu_state(struct X86_CPU_STATE *state);

void register_x86_cpu_do_interrupt_hook(x86_cpu_do_interrupt_cb cb);
void register_x86_cpu_exec_interrupt_hook_ptr(x86_cpu_exec_interrupt_cb cb);
void register_x86_cpu_do_unaligned_access_hook_ptr(x86_cpu_do_unaligned_access_cb cb);

void *save_x86_ctx_state();
void restore_x86_ctx_state(void* state);
void delete_x86_ctx_state(void* state);
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
    hwaddr precise_pc;
    uint32_t xpsr;
};


typedef bool (*do_arm_interrupt_cb)(int32_t exec_index);
void get_arm_cpu_state(struct ARM_CPU_STATE *state);
void set_arm_cpu_state(struct ARM_CPU_STATE *state);
void *save_arm_ctx_state();
void restore_arm_ctx_state(void* state);
void delete_arm_ctx_state(void* state);
void insert_nvic_intc(int irq, bool secure);
GArray* get_enabled_nvic_irq();
uint32_t* get_enabled_nvic_irq2(uint16_t **irqs);
void reset_arm_reg();
void register_arm_do_interrupt_hook(do_arm_interrupt_cb cb);
void set_armv7_vecbase(hwaddr addr);
//===================common

typedef uint64_t (*mmio_read_cb)(void *opaque,hwaddr addr_offset,unsigned size);
typedef void (*mmio_write_cb)(void *opaque,hwaddr addr_offset,uint64_t data,unsigned size);

typedef void (*pre_thread_exec_cb)(); 
typedef bool (*exec_bbl_cb)(regval pc,uint32_t id);
typedef void (*exec_ins_icmp_cb)(regval pc,uint64_t val1,uint64_t val2, int used_bits, int immediate_index); 
typedef void (*post_thread_exec_cb)(int exec_ret);




struct Simulator *create_simulator(enum XX_CPU_TYPE cpu_type,bool dbg); 
void init_simulator(struct Simulator * s);
void exec_simulator(struct Simulator *s);


void register_pre_thread_exec_hook(pre_thread_exec_cb cb);
void register_exec_bbl_hook(exec_bbl_cb cb);
void register_exec_ins_icmp_hook(exec_ins_icmp_cb cb);
void register_post_thread_exec_hook(post_thread_exec_cb cb);


MemTxResult write_ram(hwaddr addr, hwaddr size, void *buf);  //will make the page dirty
MemTxResult read_ram(hwaddr addr, hwaddr size, void *buf);
void add_ram_region(char *name,hwaddr start, hwaddr size, bool readonly);
void add_rom_region(char *name,hwaddr start, hwaddr size);
void add_mmio_region(char *name, hwaddr start, hwaddr size, mmio_read_cb mmio_read_cb, mmio_write_cb mmio_write_cb,void * opaque);
//void modify_mmio_cb(hwaddr start, hwaddr size, mmio_read_cb mmio_read_cb, mmio_write_cb mmio_write_cb,void * opaque);
void load_file_ram(char *filename,hwaddr addr, int file_offset, int size);
void load_file_rom(char *filename,hwaddr addr, int file_offset, int size);
int target_pagesize();
void clear_dirty_mem(hwaddr start, hwaddr size);
void get_dirty_pages(hwaddr addr,hwaddr size, unsigned long dirty[]);






