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

typedef uint64_t (*mmio_read_cb)(void *opaque,hwaddr addr_offset,unsigned size);
typedef void (*mmio_write_cb)(void *opaque,hwaddr addr_offset,uint64_t data,unsigned size);

typedef void (*pre_thread_exec_cb)(); 
typedef void (*exec_bbl_cb)(regval pc,uint32_t id);
typedef void (*exec_ins_icmp_cb)(regval pc,uint64_t val1,uint64_t val2, int used_bits, int immediate_index); 
typedef void (*post_thread_exec_cb)(int exec_ret);
typedef bool (*do_interrupt_cb)();



struct Simulator *create_simulator(enum XX_CPU_TYPE cpu_type,bool dbg); 
void init_simulator(struct Simulator * s);
void exec_simulator(struct Simulator *s);




void register_pre_thread_exec_hook(pre_thread_exec_cb cb);
void register_exec_bbl_hook(exec_bbl_cb cb);
void register_exec_ins_icmp_hook(exec_ins_icmp_cb cb);
void register_post_thread_exec_hook(post_thread_exec_cb cb);
void register_do_interrupt_hook(do_interrupt_cb cb);





MemTxResult write_ram(hwaddr addr, hwaddr size, void *buf);  //will make the page dirty
MemTxResult read_ram(hwaddr addr, hwaddr size, void *buf);
void add_ram_region(char *name,hwaddr start, hwaddr size);
void add_mmio_region(char *name, hwaddr start, hwaddr size, mmio_read_cb mmio_read_cb, mmio_write_cb mmio_write_cb);
void clear_dirty_mem(hwaddr start, hwaddr size);
void get_dirty_pages(hwaddr addr,hwaddr size, unsigned long dirty[]);
int target_pagesize();
void load_file(char *filename,hwaddr addr);
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


void *save_x86_ctx_state();
void restore_x86_ctx_state(void* state);
void delete_x86_ctx_state(void* state);
//===================arm
struct ARM_CPU_STATE
{
    uint32_t regs[16]; 
    uint64_t xregs[32];
};
void get_arm_cpu_state(struct ARM_CPU_STATE *state);
void set_arm_cpu_state(struct ARM_CPU_STATE *state);
void *save_arm_ctx_state();
void restore_arm_ctx_state(void* state);
void delete_arm_ctx_state(void* state);
void insert_nvic_intc(int irq, bool secure);

