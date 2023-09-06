#ifndef LOG_INCLUDED
#define LOG_INCLUDED
static inline void full_log(FILE *f,const char *msg,uint32_t append0,uint32_t append1,uint32_t append2)
{
    #ifdef DBG
    struct ARM_CPU_STATE state;
    int i = 0;
    get_arm_cpu_state(&state);
    uint32_t sp0, sp1,sp2;
    read_ram(state.regs[13],4, &sp0);
    read_ram(state.regs[13] + 4,4, &sp1);
    read_ram(state.regs[13] + 8,4, &sp2);
    fprintf(f,"%d->%s pc:%x xpsr:%x  r0:%x, r1:%x, r2:%x, r3:%x, r4:%x r5:%x r6:%x r7:%x r8:%x r9:%x r10:%x r11:%x ip:%x sp:%x lr:%x [sp]=%x, [sp+4]=%x [sp+8]=%x append0:%x append1:%x append2:%x\n",
    run_index,
    msg,
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
    state.regs[14], 
    sp0, 
    sp1,
    sp2,
    append0,
    append1,
    append2);
    #endif
}
static inline void crash_log(FILE *f,const char *msg,uint32_t append0,uint32_t append1,uint32_t append2)
{
    #ifdef CRASH_DBG
    struct ARM_CPU_STATE state;
    int i = 0;
    get_arm_cpu_state(&state);
    uint32_t sp0, sp1,sp2;
    read_ram(state.regs[13],4, &sp0);
    read_ram(state.regs[13] + 4,4, &sp1);
    read_ram(state.regs[13] + 8,4, &sp2);
    fprintf(f,"%d->%s pc:%x xpsr:%x r0:%x, r1:%x, r2:%x, r3:%x, r4:%x r5:%x r6:%x r7:%x r8:%x r9:%x r10:%x r11:%x ip:%x sp:%x lr:%x [sp]=%x, [sp+4]=%x [sp+8]=%x append0:%x append1:%x append2:%x\n",
    run_index,
    msg,
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
    state.regs[14], 
    sp0, 
    sp1,
    sp2,
    append0,
    append1,
    append2);
    #endif
}
static inline void simple_log(FILE *f,bool precise_pc,const char *msg,uint32_t append0,uint32_t append1,uint32_t append2)
{
    #ifdef DBG
    fprintf(f,"%d->%s pc:%x append0:%x append1:%x append2:%x\n",
    run_index, 
    msg,
    precise_pc ? (uint32_t)get_arm_precise_pc() : (uint32_t)get_arm_pc(),
    append0,
    append1,
    append2
    );
    #endif
}
#endif