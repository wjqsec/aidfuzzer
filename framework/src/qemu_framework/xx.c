#include <stdbool.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <glib.h>
#include "xx.h"

void qemu_init(int,char**);
bool main_loop_should_exit(int *status);
void main_loop_wait(int nonblocking);
pre_thread_exec_cb pre_thread_exec_func;
post_thread_exec_cb post_thread_exec_func;

struct Simulator *create_simulator(enum XX_CPU_TYPE cpu_type,bool dbg)
{
    struct Simulator *ret = (struct Simulator *)malloc(sizeof(struct Simulator));
    set_xx_cpu_type(cpu_type);
    ret->cpu_type = cpu_type;
    ret->enable_gdb_dbg = dbg;
    return ret;
}

void xx_register_pre_thread_exec_hook(pre_thread_exec_cb cb)
{
    pre_thread_exec_func = cb;
}
void xx_register_post_thread_exec_hook(post_thread_exec_cb cb)
{
    post_thread_exec_func = cb;
}

void load_file_ram(char *filename,hwaddr addr, int file_offset, int size)
{
    FILE *fptr = fopen(filename,"rb");
    if(!fptr)
    {
        printf("error opening %s\n",filename);
        exit(0);
    }
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
    if(!fptr)
    {
        printf("error opening %s\n",filename);
        exit(0);
    }
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
            printf("exit simulating\n");
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






