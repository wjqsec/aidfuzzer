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


typedef uint64_t (*mmio_read_cb)(void *opaque,hwaddr addr,unsigned size);
typedef void (*mmio_write_cb)(void *opaque,hwaddr addr,uint64_t data,unsigned size);

typedef void (*pre_exec_cb)(); 
typedef void (*exec_ins_cb)(); 
typedef void (*exec_bbl_cb)(); 
typedef void (*post_exec_cb)(int exec_ret);



struct Simulator *create_simulator(enum XX_CPU_TYPE cpu_type,bool dbg); 
void init_simulator(struct Simulator * s);
void exec_simulator(struct Simulator *s);




void register_pre_exec_hook(pre_exec_cb cb);
void register_exec_bbl_hook(exec_bbl_cb cb);
void register_post_exec_hook(post_exec_cb cb);





MemTxResult write_ram(hwaddr addr, hwaddr size, void *buf);
MemTxResult read_ram(hwaddr addr, hwaddr size, void *buf);
void add_ram_region(char *name,hwaddr start, hwaddr size);
void add_mmio_region(char *name, hwaddr start, hwaddr size, mmio_read_cb mmio_read_cb, mmio_write_cb mmio_write_cb);
void clear_dirty_mem(hwaddr start, hwaddr size);
void get_dirty_pages(hwaddr addr,hwaddr size, unsigned long dirty[]);

void load_file(char *filename,hwaddr addr);
//----------------x86
struct X86_CPU_STATE
{
    regval eip;
};

typedef void (*x86_cpu_do_interrupt_cb)(); 
typedef void (*x86_cpu_exec_interrupt_cb)(); 
typedef void (*x86_cpu_do_unaligned_access_cb)(); 

void get_x86_cpu_state(struct X86_CPU_STATE *state);
void set_x86_cpu_state(struct X86_CPU_STATE *state);

//===================arm
struct ARM_CPU_STATE
{
    regval eip;
};
void get_arm_cpu_state(struct ARM_CPU_STATE *state);
void set_arm_cpu_state(struct ARM_CPU_STATE *state);

