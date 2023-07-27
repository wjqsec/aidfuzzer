#ifndef IOFUZZER_INCLUDED
#define IOFUZZER_INCLUDED

#include <map>
#include <vector>
#include <set>
#include <poll.h>
using namespace std;
#include "fuzzer.h"
struct input_stream
{
    s32 priority;
    u32 offset_to_stream_area;
    stream_metadata *ptr;
};

struct queue_entry
{
    s32 depth;
    u32 edges;
    map<u32,input_stream *> *streams;
    u32 cksum;

#define DEFAULT_QUEUE_PRIORITY 1
    s32 priority;
};

struct input_model
{
    int mode;
    u32 mask;
    u32 left_shift;
    u32 size;
    u32 access_size;
    set<u32> *values;
    u32 constant_val;
    u32 init_val;
};

struct FuzzState;
struct Simulator
{
    u32 map_size;
    u8 *trace_bits;
    u8 *shared_fuzz_queue_data;
    u8 *shared_undiscovered_stream_data;

    s32 shm_id_trace_bit;
    s32 shm_id_undiscover_stream_var;
    s32 shm_id_fuzz_queue;

    int fd_ctl_to_simulator;
    int fd_ctl_from_simulator;

    int cpu;
    int pid;

    char *simulator_dump_dir;
    char *simulator_model_dir;
    char *simulator_log_dir;

#define STATUS_RUNNING 0
#define STATUS_FREE 1
    int status;

    queue_entry* fuzz_entry;
    input_stream* fuzz_stream;

    FuzzState *state;

    u32 average_exec_per_sec;


};
struct FuzzState
{
    u32 map_size;
    u32 share_size;
    u8 *virgin_bits;
    u8 *shared_stream_data;
    u32 shared_stream_used;

    u32 total_exec;
    s64 total_priority;

    vector<queue_entry*> *entries;
    vector<input_stream*> *all_queued_streams;
    map<u32,vector<input_stream*>*> *freed_streams;
    
    
    map<u32,input_model*> *models;

    map<u32,u32> *streamid_mmioaddr_mapping;

    map<u32,s32> *max_stream_used_len;

    FILE *flog;

    u64 exit_none;
    u64 exit_outofseed;
    u64 exit_timeout;
    u64 exit_crash;

    vector<Simulator *> *simulators;
#define MAX_NUM_PIPES 100
    int num_fds;
    struct pollfd fds[MAX_NUM_PIPES];

    s32 shm_id_streampool;

};

inline input_stream *allocate_new_stream(FuzzState *state,u32 id,input_stream *old , u32 len);
input_stream * allocate_freed_stream_copy_to(FuzzState *state,input_stream *old);
#endif