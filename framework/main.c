#include <stdbool.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include "xx.h"


pre_exec_cb pre_exec_func;
post_exec_cb post_exec_func;


typedef void (*qemu_init_ptr)(int,char **);
qemu_init_ptr qemu_init;

typedef int (*xx_thread_loop_ptr)(bool debug);
xx_thread_loop_ptr xx_thread_loop;

typedef enum XX_CPU_TYPE (*get_xx_cpu_type_ptr)();
get_xx_cpu_type_ptr get_xx_cpu_type;

typedef void (*set_xx_cpu_type_ptr)(enum XX_CPU_TYPE type);
set_xx_cpu_type_ptr set_xx_cpu_type;

typedef MemTxResult (*xx_ram_rw_ptr)(hwaddr addr,hwaddr len,void *buf, bool is_write);
xx_ram_rw_ptr xx_ram_rw;

typedef void (*xx_add_ram_regions_ptr)(char *name,hwaddr start, hwaddr size);
xx_add_ram_regions_ptr xx_add_ram_regions;

typedef void (*xx_add_mmio_regions_ptr)(char *name, hwaddr start, hwaddr size, void *mmio_read_cb, void *mmio_write_cb);
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

typedef void (*xx_register_do_interrupt_hook_ptr)();
xx_register_do_interrupt_hook_ptr xx_register_do_interrupt_hook;
//------------------------x86
typedef void (*register_x86_cpu_do_interrupt_hook_ptr)(x86_cpu_do_interrupt_cb cb);
register_x86_cpu_do_interrupt_hook_ptr register_x86_cpu_do_interrupt_hook;
typedef void (*register_x86_cpu_exec_interrupt_hook_ptr)(x86_cpu_exec_interrupt_cb cb);
register_x86_cpu_exec_interrupt_hook_ptr register_x86_cpu_exec_interrupt_hook;
typedef void (*register_x86_cpu_do_unaligned_access_hook_ptr)(x86_cpu_do_unaligned_access_cb cb);
register_x86_cpu_do_unaligned_access_hook_ptr register_x86_cpu_do_unaligned_access_hook;
typedef void (*xx_get_x86_cpu_state_ptr)(struct X86_CPU_STATE *state);
xx_get_x86_cpu_state_ptr xx_get_x86_cpu_state;
typedef void (*xx_set_x86_cpu_state_ptr)(struct X86_CPU_STATE *state);
xx_set_x86_cpu_state_ptr xx_set_x86_cpu_state;

void get_x86_cpu_state(struct X86_CPU_STATE *state)
{
    xx_get_x86_cpu_state(state);
}
void set_x86_cpu_state(struct X86_CPU_STATE *state)
{
    xx_set_x86_cpu_state(state);
}

//--------------------------arm
typedef void (*xx_get_arm_cpu_state_ptr)(struct ARM_CPU_STATE *state);
xx_get_arm_cpu_state_ptr xx_get_arm_cpu_state;
typedef void (*xx_set_arm_cpu_state_ptr)(struct ARM_CPU_STATE *state);
xx_set_arm_cpu_state_ptr xx_set_arm_cpu_state;
typedef void (*xx_reset_arm_reg_ptr)();
xx_reset_arm_reg_ptr xx_reset_arm_reg;
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
//---------------common
struct Simulator *create_simulator(enum XX_CPU_TYPE cpu_type,bool dbg)
{
    struct Simulator *ret = malloc(sizeof(struct Simulator));
    void *handle = NULL;
    switch (cpu_type)
    {
        case X86:
        handle = dlopen("../libqemu-system-x86_64.so", RTLD_NOW);
        break;
        case ARM:
        handle = dlopen("../libqemu-system-arm.so", RTLD_NOW);
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
    xx_add_ram_regions = dlsym(handle, "xx_add_ram_regions");
    xx_add_mmio_regions = dlsym(handle, "xx_add_mmio_regions");
    main_loop_should_exit = dlsym(handle, "main_loop_should_exit");
    main_loop_wait = dlsym(handle, "main_loop_wait");
    xx_clear_dirty_mem = dlsym(handle, "xx_clear_dirty_mem");
    xx_get_dirty_pages = dlsym(handle, "xx_get_dirty_pages");
    xx_register_exec_bbl_hook = dlsym(handle, "xx_register_exec_bbl_hook");
    xx_register_do_interrupt_hook = dlsym(handle, "xx_register_do_interrupt_hook");

    switch (cpu_type)
    {
        case X86:
        register_x86_cpu_do_interrupt_hook = dlsym(handle, "register_x86_cpu_do_interrupt_hook");
        register_x86_cpu_exec_interrupt_hook = dlsym(handle, "register_x86_cpu_exec_interrupt_hook");
        register_x86_cpu_do_unaligned_access_hook = dlsym(handle, "register_x86_cpu_do_unaligned_access_hook");
        xx_get_x86_cpu_state = dlsym(handle, "xx_get_x86_cpu_state");
        xx_set_x86_cpu_state = dlsym(handle, "xx_set_x86_cpu_state");
        break;
        case ARM:
        xx_get_arm_cpu_state = dlsym(handle, "xx_get_arm_cpu_state");
        xx_set_arm_cpu_state = dlsym(handle, "xx_set_arm_cpu_state");
        xx_reset_arm_reg = dlsym(handle, "xx_reset_arm_reg");
        break;
    }


    if(!(qemu_init && xx_thread_loop && get_xx_cpu_type && set_xx_cpu_type && xx_ram_rw && xx_add_ram_regions && xx_add_mmio_regions && main_loop_should_exit && main_loop_wait
        && xx_clear_dirty_mem && xx_get_dirty_pages && xx_register_exec_bbl_hook
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
void add_ram_region(char *name,hwaddr start, hwaddr size)
{
    xx_add_ram_regions(name,start,size);
}
void add_mmio_region(char *name, hwaddr start, hwaddr size, mmio_read_cb read_cb, mmio_write_cb write_cb)
{
    xx_add_mmio_regions(name,start,size,read_cb,write_cb);
}
void register_pre_exec_hook(pre_exec_cb cb)
{
    pre_exec_func = cb;
}
void register_post_exec_hook(post_exec_cb cb)
{
    post_exec_func = cb;
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
void load_file(char *filename,hwaddr addr)
{
    int size;
    FILE *fptr = fopen(filename,"rb");
    fseek(fptr, 0L, SEEK_END);
    size = ftell(fptr);
    fseek(fptr, 0L, SEEK_SET);
    char *tmp = (char *)malloc(size);
    fread(tmp,size,1,fptr);
    write_ram(addr,size,tmp);
    free(tmp);
}
void exec_simulator(struct Simulator *s)
{
    while(1)
    {
        int status = 0;
        if(pre_exec_func)
            pre_exec_func();
        int ret = xx_thread_loop(s->enable_gdb_dbg);
        if(post_exec_func)
            post_exec_func(ret);
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


void x86_cpu_do_interrupt_hook()
{
    struct X86_CPU_STATE state;
    get_x86_cpu_state(&state);
    printf("hook get eip:%p\n",state.eip);
}

void arm_exec_bbl()
{
    struct ARM_CPU_STATE state;
    get_arm_cpu_state(&state);
    printf("start bbl:%p\n",state.eip);
}
void x86_exec_bbl()
{
    struct X86_CPU_STATE state;
    get_x86_cpu_state(&state);
    printf("start bbl:%p\n",state.eip);
}
void arm_post_exec(int exec_ret)
{
    printf("exec exit:%d\n",exec_ret);
}

int main(int argc, char ** argv)
{
    // struct Simulator *simulator;
    // if(argc == 2)
    //     simulator = create_simulator(ARM,true);
    // else
    //     simulator = create_simulator(ARM,false);
    
    // add_ram_region("firmware",0x0, 0x80000);
    // register_exec_bbl_hook(exec_bbl);
    //add_ram_region("firmware",0xfffff000, 0x1000);
    //register_post_exec_hook(post_exec);
    //register_x86_cpu_do_interrupt_hook(x86_cpu_do_interrupt_hook);
    // init_simulator(simulator);
    // load_file("./mbed-os-example-blinky-baremetal.bin",0);
//     char buf[0x100] = {
// 0x31, 0xC0, 0x67, 0x8B, 0x00, 0xEB, 0xF9, 0x90  // xor eax,eax; mov eax,[eax] ; jmp head
// };
//     char buf[0x100] = {
// 0x31, 0xC9, 0x31, 0xC0, 0x31, 0xD2, 0xF7, 0xF1 //xor ecx,ecx; xor eax,eax; xor edx,edx; div ecx;
// };
//        char buf[0x100] = {
// 0x48, 0x31, 0xC0, 0xFF, 0xD0, 0xEB, 0xF9, 0x90  //xor rax,rax; call rax; jmp head
// };
    // char buf[0x100] = {0xeb, 0xfe};  //jmp self
//     char buf[0x100] = {
// 0x90, 0xEB, 0x01, 0x90, 0x90, 0xEB, 0x01, 0x90, 0x90, 0xEB, 0xF5, 0x90, 0x00, 0x00, 0x00, 0x00  // nop jmp1 nop; nop jmp2 nop; nop jmp head nop;
// };
//     write_ram(0xfffff000,0x10,buf);   
//     struct X86_CPU_STATE state;
//     state.eip = 0xf000;
//     set_x86_cpu_state(&state);
    
    // clear_dirty_mem(0xfffff000,0x1000);
    // unsigned long dirty[1000];
    // memset(dirty, 0x12, sizeof(dirty));
    // get_dirty_pages(0xfffff000,0x1000, dirty);
    // printf("%x\n",dirty[0]);
    // exec_simulator(simulator);
    


    struct Simulator *simulator;
    if(argc == 2)
        simulator = create_simulator(ARM,true);
    else
        simulator = create_simulator(ARM,false);
    add_ram_region("firmware",0x0, 0x80000);
    add_ram_region("on-chip-ram",0x10000000, 0x8000);
    register_exec_bbl_hook(arm_exec_bbl);
    //register_post_exec_hook(arm_post_exec);
    init_simulator(simulator);
    load_file("./mbed-os-example-blinky-baremetal.bin",0);
    //xx_register_do_interrupt_hook();
    reset_arm_reg();
    exec_simulator(simulator);


//     struct Simulator *simulator;
//     if(argc == 2)
//         simulator = create_simulator(X86,true);
//     else
//         simulator = create_simulator(X86,false);
//     add_ram_region("firmware",0xfffff000, 0x1000);
//     register_exec_bbl_hook(x86_exec_bbl);
//     init_simulator(simulator);
//     char buf[0x100] = {
// 0x90, 0xEB, 0x01, 0x90, 0x90, 0xEB, 0x01, 0x90, 0x90, 0xEB, 0xF5, 0x90, 0x00, 0x00, 0x00, 0x00  // nop jmp1 nop; nop jmp2 nop; nop jmp head nop;
// };
//     write_ram(0xfffff000,0x10,buf);
//     exec_simulator(simulator);
}