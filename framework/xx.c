#include <stdbool.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <glib.h>
#include "xx.h"


pre_thread_exec_cb pre_thread_exec_func;
post_thread_exec_cb post_thread_exec_func;



typedef void (*qemu_init_ptr)(int,char **);
qemu_init_ptr qemu_init;

typedef int (*xx_thread_loop_ptr)(bool debug);
xx_thread_loop_ptr xx_thread_loop;

typedef enum XX_CPU_TYPE (*get_xx_cpu_type_ptr)();
get_xx_cpu_type_ptr get_xx_cpu_type;

typedef void (*set_xx_cpu_type_ptr)(enum XX_CPU_TYPE type);
set_xx_cpu_type_ptr set_xx_cpu_type;

typedef MemTxResult (*xx_rom_write_ptr)(hwaddr addr,void *buf, hwaddr len);
xx_rom_write_ptr xx_rom_write;

typedef MemTxResult (*xx_ram_rw_ptr)(hwaddr addr,hwaddr len,void *buf, bool is_write);
xx_ram_rw_ptr xx_ram_rw;

typedef void (*xx_add_ram_regions_ptr)(char *name,hwaddr start, hwaddr size, bool readonly);
xx_add_ram_regions_ptr xx_add_ram_regions;

typedef void (*xx_add_mmio_regions_ptr)(char *name, hwaddr start, hwaddr size, void *mmio_read_cb, void *mmio_write_cb, void *opaque);
xx_add_mmio_regions_ptr xx_add_mmio_regions;

typedef bool (*main_loop_should_exit_ptr)(int *status);
main_loop_should_exit_ptr main_loop_should_exit;

typedef void (*main_loop_wait_ptr)(int nonblocking);
main_loop_wait_ptr main_loop_wait;

typedef void (*xx_clear_dirty_mem_ptr)(hwaddr addr, hwaddr size);
xx_clear_dirty_mem_ptr xx_clear_dirty_mem;

typedef void (*xx_get_dirty_pages_ptr)(hwaddr addr,hwaddr size, unsigned long dirty[]);
xx_get_dirty_pages_ptr xx_get_dirty_pages;

typedef void (*xx_register_exec_bbl_hook_ptr)(exec_bbl_cb cb);
xx_register_exec_bbl_hook_ptr xx_register_exec_bbl_hook;

typedef int (*xx_target_pagesize_ptr)();
xx_target_pagesize_ptr xx_target_pagesize;

typedef void (*xx_register_exec_ins_icmp_hook_ptr)(exec_ins_icmp_cb cb);
xx_register_exec_ins_icmp_hook_ptr xx_register_exec_ins_icmp_hook;

typedef void (*xx_add_rom_region_ptr)(char *name,hwaddr start, hwaddr size);
xx_add_rom_region_ptr xx_add_rom_region;

// typedef void (*xx_modify_mmio_cb_ptr)(hwaddr start, hwaddr size, void * mmio_read_cb, void * mmio_write_cb,void * opaque);
// xx_modify_mmio_cb_ptr xx_modify_mmio_cb;
//------------------------x86
typedef void (*xx_register_x86_cpu_do_interrupt_hook_ptr)(x86_cpu_do_interrupt_cb cb);
xx_register_x86_cpu_do_interrupt_hook_ptr xx_register_x86_cpu_do_interrupt_hook;
typedef void (*xx_register_x86_cpu_exec_interrupt_hook_ptr)(x86_cpu_exec_interrupt_cb cb);
xx_register_x86_cpu_exec_interrupt_hook_ptr xx_register_x86_cpu_exec_interrupt_hook;
typedef void (*xx_register_x86_cpu_do_unaligned_access_hook_ptr)(x86_cpu_do_unaligned_access_cb cb);
xx_register_x86_cpu_do_unaligned_access_hook_ptr xx_register_x86_cpu_do_unaligned_access_hook;
typedef void (*xx_get_x86_cpu_state_ptr)(struct X86_CPU_STATE *state);
xx_get_x86_cpu_state_ptr xx_get_x86_cpu_state;
typedef void (*xx_set_x86_cpu_state_ptr)(struct X86_CPU_STATE *state);
xx_set_x86_cpu_state_ptr xx_set_x86_cpu_state;
typedef void * (*xx_save_x86_ctx_state_ptr)();
xx_save_x86_ctx_state_ptr xx_save_x86_ctx_state;
typedef void (*xx_restore_x86_ctx_state_ptr)(void* state);
xx_restore_x86_ctx_state_ptr xx_restore_x86_ctx_state;
typedef void (*xx_delete_x86_ctx_state_ptr)(void* state);
xx_delete_x86_ctx_state_ptr xx_delete_x86_ctx_state;


void get_x86_cpu_state(struct X86_CPU_STATE *state)
{
    xx_get_x86_cpu_state(state);
}
void set_x86_cpu_state(struct X86_CPU_STATE *state)
{
    xx_set_x86_cpu_state(state);
}
void *save_x86_ctx_state()
{
    return xx_save_x86_ctx_state();
}
void restore_x86_ctx_state(void* state)
{
    xx_restore_x86_ctx_state(state);
}
void delete_x86_ctx_state(void* state)
{
    xx_delete_x86_ctx_state(state);
}
void register_x86_cpu_do_interrupt_hook(x86_cpu_do_interrupt_cb cb)
{
    xx_register_x86_cpu_do_interrupt_hook(cb);
}
void register_x86_cpu_exec_interrupt_hook(x86_cpu_exec_interrupt_cb cb)
{
    xx_register_x86_cpu_exec_interrupt_hook(cb);
}
void register_x86_cpu_do_unaligned_access_hook(x86_cpu_do_unaligned_access_cb cb)
{
    xx_register_x86_cpu_do_unaligned_access_hook(cb);
}
//--------------------------arm
typedef void (*xx_get_arm_cpu_state_ptr)(struct ARM_CPU_STATE *state);
xx_get_arm_cpu_state_ptr xx_get_arm_cpu_state;
typedef void (*xx_set_arm_cpu_state_ptr)(struct ARM_CPU_STATE *state);
xx_set_arm_cpu_state_ptr xx_set_arm_cpu_state;
typedef void (*xx_reset_arm_reg_ptr)();
xx_reset_arm_reg_ptr xx_reset_arm_reg;
typedef void*(*xx_save_arm_ctx_state_ptr)();
xx_save_arm_ctx_state_ptr xx_save_arm_ctx_state;
typedef void (*xx_restore_arm_ctx_state_ptr)(void* state);
xx_restore_arm_ctx_state_ptr xx_restore_arm_ctx_state;
typedef void (*xx_delete_arm_ctx_state_ptr)(void* state);
xx_delete_arm_ctx_state_ptr xx_delete_arm_ctx_state;
typedef void (*xx_insert_nvic_intc_ptr)(int irq, bool secure);
xx_insert_nvic_intc_ptr xx_insert_nvic_intc;
typedef void (*xx_register_arm_do_interrupt_hook_ptr)(do_arm_interrupt_cb cb);
xx_register_arm_do_interrupt_hook_ptr xx_register_arm_do_interrupt_hook;
typedef void (*xx_set_armv7_vecbase_ptr)(hwaddr addr);
xx_set_armv7_vecbase_ptr xx_set_armv7_vecbase;
typedef GArray* (*xx_get_enabled_nvic_irq_ptr)();
xx_get_enabled_nvic_irq_ptr xx_get_enabled_nvic_irq;
typedef uint32_t* (*xx_get_enabled_nvic_irq2_ptr)(uint16_t **irqs);
xx_get_enabled_nvic_irq2_ptr xx_get_enabled_nvic_irq2;

void get_arm_cpu_state(struct ARM_CPU_STATE *state)
{
    xx_get_arm_cpu_state(state);
}
void set_arm_cpu_state(struct ARM_CPU_STATE *state)
{
    xx_set_arm_cpu_state(state);
}
void reset_arm_reg()
{
    xx_reset_arm_reg();
}
void *save_arm_ctx_state()
{
    return xx_save_arm_ctx_state();
}
void restore_arm_ctx_state(void* state)
{
    xx_restore_arm_ctx_state(state);
}
void delete_arm_ctx_state(void* state)
{
    xx_delete_arm_ctx_state(state);
}
void insert_nvic_intc(int irq, bool secure)
{
    xx_insert_nvic_intc(irq,secure);
}
void register_arm_do_interrupt_hook(do_arm_interrupt_cb cb)
{
    xx_register_arm_do_interrupt_hook(cb);
}
void set_armv7_vecbase(hwaddr addr)
{
    xx_set_armv7_vecbase(addr);
}
GArray* get_enabled_nvic_irq()
{
    return xx_get_enabled_nvic_irq();
}
uint32_t* get_enabled_nvic_irq2(uint16_t **irqs)
{
    return xx_get_enabled_nvic_irq2(irqs);
}
//---------------common
struct Simulator *create_simulator(enum XX_CPU_TYPE cpu_type,bool dbg)
{
    struct Simulator *ret = malloc(sizeof(struct Simulator));
    void *handle = NULL;
    switch (cpu_type)
    {
        case X86:
        handle = dlopen("/home/w/hd/iofuzzer/xxfuzzer/qemu-7.2.0/build/libqemu-system-x86_64.so", RTLD_NOW);
        break;
        case ARM:
        handle = dlopen("/home/w/hd/iofuzzer/xxfuzzer/qemu-7.2.0/build/libqemu-system-arm.so", RTLD_NOW);
        break;
    }
    if (!handle) {
        fprintf(stderr, "%s\n", dlerror());
        exit(EXIT_FAILURE);
    }
    qemu_init = dlsym(handle, "qemu_init");
    xx_thread_loop = dlsym(handle, "xx_thread_loop");
    get_xx_cpu_type = dlsym(handle, "get_xx_cpu_type");
    set_xx_cpu_type = dlsym(handle, "set_xx_cpu_type");
    xx_ram_rw = dlsym(handle, "xx_ram_rw");
    xx_rom_write = dlsym(handle, "xx_rom_write");
    xx_add_ram_regions = dlsym(handle, "xx_add_ram_regions");
    xx_add_mmio_regions = dlsym(handle, "xx_add_mmio_regions");
    main_loop_should_exit = dlsym(handle, "main_loop_should_exit");
    main_loop_wait = dlsym(handle, "main_loop_wait");
    xx_clear_dirty_mem = dlsym(handle, "xx_clear_dirty_mem");
    xx_get_dirty_pages = dlsym(handle, "xx_get_dirty_pages");
    xx_register_exec_bbl_hook = dlsym(handle, "xx_register_exec_bbl_hook");
    xx_target_pagesize = dlsym(handle, "xx_target_pagesize");
    xx_register_exec_ins_icmp_hook = dlsym(handle, "xx_register_exec_ins_icmp_hook");
    xx_add_rom_region = dlsym(handle, "xx_add_rom_region");
    //xx_modify_mmio_cb = dlsym(handle, "xx_modify_mmio_cb");
    switch (cpu_type)
    {
        case X86:
        xx_register_x86_cpu_do_interrupt_hook = dlsym(handle, "xx_register_x86_cpu_do_interrupt_hook");
        xx_register_x86_cpu_exec_interrupt_hook = dlsym(handle, "xx_register_x86_cpu_exec_interrupt_hook");
        xx_register_x86_cpu_do_unaligned_access_hook = dlsym(handle, "xx_register_x86_cpu_do_unaligned_access_hook");
        xx_get_x86_cpu_state = dlsym(handle, "xx_get_x86_cpu_state");
        xx_set_x86_cpu_state = dlsym(handle, "xx_set_x86_cpu_state");
        xx_save_x86_ctx_state = dlsym(handle, "xx_save_x86_ctx_state");
        xx_restore_x86_ctx_state = dlsym(handle, "xx_restore_x86_ctx_state");
        xx_delete_x86_ctx_state = dlsym(handle, "xx_delete_x86_ctx_state");
        break;
        case ARM:
        xx_get_arm_cpu_state = dlsym(handle, "xx_get_arm_cpu_state");
        xx_set_arm_cpu_state = dlsym(handle, "xx_set_arm_cpu_state");
        xx_reset_arm_reg = dlsym(handle, "xx_reset_arm_reg");
        xx_save_arm_ctx_state = dlsym(handle, "xx_save_arm_ctx_state");
        xx_restore_arm_ctx_state = dlsym(handle, "xx_restore_arm_ctx_state");
        xx_delete_arm_ctx_state = dlsym(handle, "xx_delete_arm_ctx_state");
        xx_insert_nvic_intc = dlsym(handle, "xx_insert_nvic_intc");
        xx_register_arm_do_interrupt_hook = dlsym(handle, "xx_register_arm_do_interrupt_hook");
        xx_set_armv7_vecbase = dlsym(handle, "xx_set_armv7_vecbase");
        xx_get_enabled_nvic_irq = dlsym(handle, "xx_get_enabled_nvic_irq");
        xx_get_enabled_nvic_irq2 = dlsym(handle, "xx_get_enabled_nvic_irq2");
        break;
    }


    if(!(qemu_init && xx_thread_loop && get_xx_cpu_type && 
    set_xx_cpu_type && xx_ram_rw && xx_add_ram_regions && 
    xx_add_mmio_regions && main_loop_should_exit && main_loop_wait 
    && xx_clear_dirty_mem && xx_get_dirty_pages && xx_register_exec_bbl_hook &&
    xx_target_pagesize && xx_register_exec_ins_icmp_hook && xx_add_rom_region
    ))
    {
        printf("symbol not found\n");
        exit(0);
    }
    if(cpu_type == X86 && !(
        xx_register_x86_cpu_do_interrupt_hook && xx_register_x86_cpu_exec_interrupt_hook &&
        xx_register_x86_cpu_do_unaligned_access_hook && xx_get_x86_cpu_state &&
        xx_set_x86_cpu_state && xx_save_x86_ctx_state && xx_restore_x86_ctx_state &&
        xx_delete_x86_ctx_state
    ))
    {
        printf("symbol not found\n");
        exit(0);
    }
    if(cpu_type == ARM && !(
        xx_get_arm_cpu_state && xx_set_arm_cpu_state && xx_reset_arm_reg &&
        xx_save_arm_ctx_state && xx_restore_arm_ctx_state && xx_delete_arm_ctx_state &&
        xx_insert_nvic_intc && xx_register_arm_do_interrupt_hook && xx_set_armv7_vecbase &&
        xx_get_enabled_nvic_irq && xx_get_enabled_nvic_irq2
    ))
    {
        printf("symbol not found\n");
        exit(0);
    }

    set_xx_cpu_type(cpu_type);
    ret->cpu_type = cpu_type;
    ret->enable_gdb_dbg = dbg;
    return ret;
}

MemTxResult write_ram(hwaddr addr, hwaddr size, void *buf)
{
    xx_ram_rw(addr,size,buf,true);
}
MemTxResult read_ram(hwaddr addr, hwaddr size, void *buf)
{
    xx_ram_rw(addr,size,buf,false);
}
void add_ram_region(char *name,hwaddr start, hwaddr size, bool readonly)
{
    xx_add_ram_regions(name,start,size,readonly);
}
void add_rom_region(char *name,hwaddr start, hwaddr size)
{
    xx_add_rom_region(name,start,size);
}
void add_mmio_region(char *name, hwaddr start, hwaddr size, mmio_read_cb read_cb, mmio_write_cb write_cb, void *opaque)
{
    xx_add_mmio_regions(name,start,size,read_cb,write_cb,opaque);
}
// void modify_mmio_cb(hwaddr start, hwaddr size, mmio_read_cb mmio_read_cb, mmio_write_cb mmio_write_cb,void * opaque)
// {
//     xx_modify_mmio_regions(start,size,mmio_read_cb,mmio_write_cb,opaque);
// }
void register_pre_thread_exec_hook(pre_thread_exec_cb cb)
{
    pre_thread_exec_func = cb;
}
void register_post_thread_exec_hook(post_thread_exec_cb cb)
{
    post_thread_exec_func = cb;
}

void register_exec_bbl_hook(exec_bbl_cb cb)
{
    xx_register_exec_bbl_hook(cb);
}
void clear_dirty_mem(hwaddr start, hwaddr size)
{
    xx_clear_dirty_mem(start,size);
}
void get_dirty_pages(hwaddr addr,hwaddr size, unsigned long dirty[])
{
    xx_get_dirty_pages(addr,size,dirty);
}
int target_pagesize()
{
    return xx_target_pagesize();
}
void register_exec_ins_icmp_hook(exec_ins_icmp_cb cb)
{
    xx_register_exec_ins_icmp_hook(cb);
}
void load_file_ram(char *filename,hwaddr addr, int file_offset, int size)
{
    FILE *fptr = fopen(filename,"rb");
    fseek(fptr, 0, SEEK_END);
    long remainder_size = ftell(fptr) - file_offset;
    fseek(fptr, file_offset, SEEK_SET);
    size = size < remainder_size ? size : remainder_size;
    char *tmp = (char *)malloc(size);
    fread(tmp,size,1,fptr);
    write_ram(addr,size,tmp);
    free(tmp);
    fclose(fptr);
}
void load_file_rom(char *filename,hwaddr addr, int file_offset, int size)
{
    FILE *fptr = fopen(filename,"rb");
    fseek(fptr, 0, SEEK_END);
    long remainder_size = ftell(fptr) - file_offset;
    fseek(fptr, file_offset, SEEK_SET);
    size = size < remainder_size ? size : remainder_size;
    char *tmp = (char *)malloc(size);
    fread(tmp,size,1,fptr);
    xx_rom_write(addr,tmp,size);
    free(tmp);
    fclose(fptr);
}
void exec_simulator(struct Simulator *s)
{
    while(1)
    {
        int status = 0;
        if(pre_thread_exec_func)
            pre_thread_exec_func();
        int ret = xx_thread_loop(s->enable_gdb_dbg);
        if(post_thread_exec_func)
            post_thread_exec_func(ret);
        if(!main_loop_should_exit(&status))
        {
            main_loop_wait(false);
        }
        else
        {
            break;
        }
    }
    
}
void init_simulator(struct Simulator * s)
{
    int argc = 0;
    char* args_qemu[20];
    args_qemu[argc++] = "qemu"; 
    args_qemu[argc++] = "-accel"; 
    args_qemu[argc++] = "xx"; 
    args_qemu[argc++] = "-M"; 
    args_qemu[argc++] = "xx";
    args_qemu[argc++] = "-nographic";  
    if(s->enable_gdb_dbg)
    {
        args_qemu[argc++] = "-s"; 
        args_qemu[argc++] = "-S"; 
    }
    qemu_init(argc, args_qemu);
}






