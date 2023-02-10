typedef uint64_t hwaddr;


enum CPU_TYPE 
{
    x86_64
};


struct Simulator
{
    CPU_TYPE cpu_type;

};

struct MemoryRegion
{
    hwaddr start;
    hwaddr size;
    int perm_read:1;
    int perm_write:1;
    int perm_exec:1;
};

typedef void (*mmio_cb)(); 

typedef void (*pre_exec_cb)(); 
typedef void (*exec_ins_cb)(); 
typedef void (*exec_bbl_cb)(); 
typedef void (*post_exec_cb)(); 

struct Simulator *create_simulator(CPU_TYPE cpu_type); 

void add_ram_region(struct MemoryRegion *region, void *data, int size);
void add_mmio_region(struct MemoryRegion *region, mmio_cb cb);

void register_pre_exec_hook(pre_exec_cb cb);
void register_exec_ins_hook(exec_ins_cb cb);
void register_exec_bbl_hook(exec_bbl_cb cb);
void register_post_exec_hook(post_exec_cb cb);

void exec_simulator(struct Simulator *simulator);