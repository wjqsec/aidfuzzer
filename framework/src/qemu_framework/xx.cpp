#include <stdbool.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <glib.h>
#include "xx.h"



pre_thread_exec_cb pre_thread_exec_func;
post_thread_exec_cb post_thread_exec_func;

XXSimulator *create_simulator(bool dbg)
{
    XXSimulator *ret = (XXSimulator *)malloc(sizeof(XXSimulator));
    ret->enable_gdb_dbg = dbg;
    return ret;
}

void register_pre_thread_exec_hook(pre_thread_exec_cb cb)
{
    pre_thread_exec_func = cb;
}
void register_post_thread_exec_hook(post_thread_exec_cb cb)
{
    post_thread_exec_func = cb;
}

void load_file_ram(void *ptr,char *filename, int file_offset, int mem_offset, int file_size, int mem_size)
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
    if(file_size == 0)
    {
        file_size = remainder_size;
    }
    else
        file_size = file_size < remainder_size ? file_size : remainder_size;
    if (file_size > mem_size)
        file_size = mem_size;
        
    fread((uint8_t*)ptr + mem_offset,file_size,1,fptr);
    fclose(fptr);
}
void zero_ram(void *ptr,hw_addr size)
{
    memset(ptr,0,size);
}
void load_file_rom(char *filename,hw_addr addr, int file_offset, int mem_offset, int file_size)
{
    printf("load_file_rom not support yes\n");
    // FILE *fptr = fopen(filename,"rb");
    // if(!fptr)
    // {
    //     printf("error opening %s\n",filename);
    //     exit(0);
    // }
    // fseek(fptr, 0, SEEK_END);
    // long remainder_size = ftell(fptr) - file_offset;
    // fseek(fptr, file_offset, SEEK_SET);
    // size = size < remainder_size ? size : remainder_size;
    // char *tmp = (char *)malloc(size);
    // fread(tmp,size,1,fptr);
    // xx_rom_write(addr,tmp,size);
    // free(tmp);
    // fclose(fptr);
}
void exec_simulator(XXSimulator *s)
{
    while(1)
    {
        int status = 0;
        if(pre_thread_exec_func)
            pre_thread_exec_func();
        int ret = thread_loop(s->enable_gdb_dbg);
        if(post_thread_exec_func)
            post_thread_exec_func(ret);
        // if(!main_loop_should_exit(&status))
        // {
        //     main_loop_wait(false);
        // }
        // else
        // {
        //     printf("exit simulating\n");
        //     break;
        // }
    }
    
}
void init_simulator(XXSimulator * s)
{
    int argc = 0;
    char* args_qemu[30];
    args_qemu[argc++] = (char *)"qemu"; 
    args_qemu[argc++] = (char *)"-accel"; 
    args_qemu[argc++] = (char *)"xx"; 
    args_qemu[argc++] = (char *)"-M"; 
    args_qemu[argc++] = (char *)"xx";
    args_qemu[argc++] = (char *)"-nographic";  
    if(s->enable_gdb_dbg)
    {
        args_qemu[argc++] = (char *)"-s"; 
        args_qemu[argc++] = (char *)"-S"; 
    }
    qemu_init(argc, args_qemu);
}






