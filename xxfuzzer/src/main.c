#include "xxfuzzer.h"
#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>


typedef void (*qemu_init_ptr)(int,char **);
static qemu_init_ptr qemu_init;

typedef void (*xxfuzzer_thread_loop_ptr)(bool);
xxfuzzer_thread_loop_ptr xxfuzzer_thread_loop;


struct Simulator *create_simulator(CPU_TYPE cpu_type)
{
    struct Simulator *ret = malloc(sizeof(struct Simulator));
    void *handle = dlopen("../libqemu-system-x86_64.so", RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "%s\n", dlerror());
        exit(EXIT_FAILURE);
    }
    qemu_init = dlsym(handle, "qemu_init");
    xxfuzzer_thread_loop = dlsym(handle, "xxfuzzer_thread_loop");

    char ** args_qemu = {"-accel", "xxfuzzer","-M","xxfuzzer","-nographic",0};
    qemu_init(sizeof(args_qemu), args_qemu);
    xxfuzzer_thread_loop(false);
    return ret;
}

void exec_simulator(struct Simulator *simulator)
{

}
int main(int argc, char ** argv)
{
    struct Simulator *simulator = create_simulator(x86_64);
    exec_simulator(simulator);
}