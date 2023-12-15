#ifndef LOG_INCLUDED
#define LOG_INCLUDED


static void append_full_ctx_string(FILE *f)
{
    ARM_CPU_STATE state;
    get_arm_cpu_state(&state);
    fprintf(f,"pc:%x  xpsr:%x  r0:%x, r1:%x, r2:%x, r3:%x, r4:%x r5:%x r6:%x r7:%x r8:%x r9:%x r10:%x r11:%x ip:%x sp:%x lr:%x",
    state.regs[15], 
    state.xpsr,
    state.regs[0],
    state.regs[1],
    state.regs[2],
    state.regs[3],
    state.regs[4],
    state.regs[5],
    state.regs[6],
    state.regs[7],
    state.regs[8],
    state.regs[9],
    state.regs[10],
    state.regs[11],
    state.regs[12],
    state.regs[13],
    state.regs[14]);
}
static void append_simple_ctx_string(FILE *f)
{
    ARM_CPU_STATE state;
    get_arm_cpu_state(&state);
    fprintf(f,"r0:%x, r1:%x, r2:%x, r3:%x, r4:%x r5:%x",
    state.regs[0],
    state.regs[1],
    state.regs[2],
    state.regs[3],
    state.regs[4],
    state.regs[5]);
}

#endif