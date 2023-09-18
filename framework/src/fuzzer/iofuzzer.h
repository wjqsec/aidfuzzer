#ifndef IOFUZZER_INCLUDED
#define IOFUZZER_INCLUDED

#include <map>
#include <vector>
#include <set>
#include <poll.h>
using namespace std;
#include "fuzzer.h"


#define MODE_FUZZ 1
#define MODE_DEBUG 2
#define MODE_RUN 3


struct input_stream
{

    u32 offset_to_stream_area;
    s32 ref_count;
    u8 offset_to_save[0];
    stream_metadata *ptr;

}__attribute__((packed));

struct queue_entry
{
    s32 depth;
    u32 edges;
    u32 cksum;
#define DEFAULT_QUEUE_PRIORITY 1
    s32 priority;
    u64 fuzztimes;
    u8 offset_to_save[0];
    
#define DEFAULT_STREAM_PRIORITY 1
    map<u32,input_stream *> *streams;
    map<u32,s32> *streams_priority;
    
}__attribute__((packed));

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

    s32 shm_id_trace_bit;
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
#define STATUS_EXIT 2
#define STATUS_KILLED 3
    int status;

    queue_entry* base_entry;
    queue_entry* fuzz_entry;
    u32 fuzz_stream_id;
    bool onlyrun;
    map<u32,int> *id_queue_idx_mapping;


    FuzzState *state;

};
struct FuzzState
{
    u32 map_size;
    u32 share_size;
    u8 *virgin_bits;
    u8 *shared_stream_data;
    s32 shm_id_streampool;

    u32 shared_stream_used;
    

    u32 total_exec;
    s64 total_priority;

    vector<queue_entry*> *entries;
    map<u32,vector<input_stream*>*> *freed_streams;
    set<u32> *crash_ids;
    vector<queue_entry*> *crashes;


    map<u32,input_model*> *models;
    map<u32,u32> *streamid_mmioaddr_mapping;

    FILE *flog;

    u64 exit_reason[EXIT_MAX];

    vector<Simulator *> *simulators;
#define MAX_NUM_PIPES 100
    int num_fds;
    struct pollfd fds[MAX_NUM_PIPES];

};




void fuzz_one_post(FuzzState *state,Simulator *simulator);
void show_stat(FuzzState *state);
#endif