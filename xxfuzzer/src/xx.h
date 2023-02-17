typedef uint64_t hwaddr;
typedef uint32_t MemTxResult;

enum XX_CPU_TYPE 
{
    X86,
    ARM
};


struct Simulator
{
    enum XX_CPU_TYPE cpu_type;

};


typedef uint64_t (*mmio_read_cb)(void *opaque,hwaddr addr,unsigned size);
typedef void (*mmio_write_cb)(void *opaque,hwaddr addr,uint64_t data,unsigned size);
typedef void (*start_simulation_cb)();
typedef void (*pre_exec_cb)(); 
typedef void (*exec_ins_cb)(); 
typedef void (*exec_bbl_cb)(); 
typedef void (*post_exec_cb)();
typedef void (*end_simulation_cb)();


struct Simulator *create_simulator(enum XX_CPU_TYPE cpu_type); 
void init_simulator();
void exec_simulator(bool debug);



void register_start_simulation_hook(start_simulation_cb cb);
void register_pre_exec_hook(pre_exec_cb cb);
void register_exec_ins_hook(exec_ins_cb cb);
void register_exec_bbl_hook(exec_bbl_cb cb);
void register_post_exec_hook(post_exec_cb cb);
void register_end_simulation_hook(end_simulation_cb cb);




MemTxResult write_ram(hwaddr addr, hwaddr size, void *buf);
MemTxResult read_ram(hwaddr addr, hwaddr size, void *buf);
void add_ram_region(char *name,hwaddr start, hwaddr size);
void add_mmio_region(char *name, hwaddr start, hwaddr size, mmio_read_cb mmio_read_cb, mmio_write_cb mmio_write_cb);