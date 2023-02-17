#include <stdbool.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include "xx.h"


pre_exec_cb pre_exec_func;
post_exec_cb post_exec_func;

start_simulation_cb start_simulation_func;
end_simulation_cb end_simulation_func;


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

struct Simulator *create_simulator(enum XX_CPU_TYPE cpu_type)
{
    struct Simulator *ret = malloc(sizeof(struct Simulator));
    void *handle = dlopen("../libqemu-system-x86_64.so", RTLD_NOW);
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

    if(!(qemu_init && xx_thread_loop && get_xx_cpu_type && xx_ram_rw && xx_add_ram_regions && xx_add_mmio_regions && main_loop_should_exit && main_loop_wait))
    {
        printf("symbol not found\n");
        exit(0);
    }
        

    set_xx_cpu_type(cpu_type);
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
void register_start_simulation_hook(start_simulation_cb cb)
{
    start_simulation_func = cb;
}
void register_end_simulation_hook(end_simulation_cb cb)
{
    end_simulation_func = cb;
}


void exec_simulator(bool debug)
{
    if(start_simulation_func)
        start_simulation_func();
    while(1)
    {
        int status = 0;
        if(pre_exec_func)
            pre_exec_func();
        xx_thread_loop(debug);
        if(post_exec_func)
            post_exec_func();
        if(!main_loop_should_exit(&status))
        {
            main_loop_wait(false);
        }
        else
        {
            break;
        }
    }
    if(end_simulation_func)
        end_simulation_func();
    
}

void init_simulator()
{
    char* args_qemu[] = {"qemu","-accel", "xx","-M","xx","-nographic"};

    qemu_init(6, args_qemu);
}
int main(int argc, char ** argv)
{
    struct Simulator *simulator = create_simulator(X86);
    add_ram_region("bios",0xfffffff0, 0x1000);
    init_simulator();

//     char buf[0x100] = {
// 0x31, 0xC0, 0x67, 0x8B, 0x00, 0xEB, 0xF9, 0x90  // xor eax,eax; mov eax,[eax] ; jmp head
// };
//     char buf[0x100] = {
// 0x31, 0xC9, 0x31, 0xC0, 0x31, 0xD2, 0xF7, 0xF1 //xor ecx,ecx; xor eax,eax; xor edx,edx; div ecx;
// };
    char buf[0x100] = {0xeb, 0xfe};  //jmp self

    write_ram(0xfffffff0,0x100,buf);   
    
    exec_simulator(true);
}