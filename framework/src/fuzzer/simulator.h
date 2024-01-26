#ifndef SIMULATOR_INCLUDED
#define SIMULATOR_INCLUDED

#include "iofuzzer.h"

void fuzz_start(Simulator *simulator);
void fuzz_continue(Simulator *simulator);
void fuzz_terminate(Simulator *simulator);
void fuzz_exit(Simulator *simulator,EXIT_INFO *exit_info);
void fuzz_exit_timeout(Simulator *simulator,EXIT_INFO *exit_info, u32 seconds, bool *timeout);
Simulator* get_avaliable_simulator(FuzzState *state);
void wait_forkserver_terminate(Simulator * simulator);
void fuzz_continue_stream_notfound(Simulator *simulator,input_stream *new_stream);
void fuzz_continue_stream_outof(Simulator *simulator,input_stream *new_stream);
void simulator_env_init(void);
void simulator_classify_count(Simulator * simulator);
void simulator_task(Simulator *simulator,queue_entry* fuzz_entry,queue_entry* base_entry, set<u32> *fuzz_streams);
void kill_cleanup_simulator(FuzzState *state,int pid);
void allocate_new_simulator(FuzzState *state, int affinity);
EXIT_INFO run_input(FuzzState *state,queue_entry* fuzz_entry,Simulator **out_simulator);
void wait_all_simualtor_finish_task(FuzzState *state);
#endif