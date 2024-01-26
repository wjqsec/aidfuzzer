#ifndef IOFUZZER_INCLUDED
#define IOFUZZER_INCLUDED

#include <map>
#include <vector>
#include <set>
#include <string>
#include <poll.h>
#include <linux/limits.h>

#include "fuzzer.h"

using namespace std;



struct input_stream
{

    u32 offset_to_stream_area;
    s32 ref_count;
    u8 offset_to_save[0];
    stream_metadata *ptr;

}__attribute__((packed));

struct stream_schedule_info
{
    u64 schedule_times;
    u64 interesting_times;
    u64 weight;
};

struct queue_entry
{
    s32 depth;
    u32 edges;
    u32 cksum;
#define DEFAULT_QUEUE_PRIORITY 1
#define DEFAULT_STREAM_PRIORITY 1
    s32 priority;
    u32 exit_reason;
    u64 fuzztimes;
    u64 create_time;
    u8 offset_to_save[0];
    
#define DEFAULT_STREAM_PRIORITY 1
    map<u32,input_stream *> *streams;
    
}__attribute__((packed));

struct crash_info
{
    u64 pc;
    u64 lr;
};
struct input_model
{
    u32 mmio_addr;
    u32 pc_addr;

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

#define STATUS_RUNNING 0
#define STATUS_FREE 1
#define STATUS_EXIT 2
#define STATUS_KILLED 3
    int status;

    struct
    {
        queue_entry* base_entry;
        queue_entry* fuzz_entry;
        set<u32> * fuzz_streams;
        map<u32,int> *id_queue_idx_mapping;
    } task;

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

    s64 total_queue_priority;
    vector<queue_entry*> *entries;

    map<u32,vector<input_stream*>*> *freed_streams;
    vector<crash_info> *crashes;

    map<u32,stream_schedule_info *> *stream_schedule_info;
    map<u32,input_model*> *models;

    FILE *flog;

    u64 exit_reason[EXIT_MAX];

    vector<Simulator *> *simulators;
#define MAX_NUM_PIPES 100
    int num_fds;
    struct pollfd fds[MAX_NUM_PIPES];

    u64 start_time;
    u32 total_unique_bbls;

    bool use_fuzzware;
    int max_bbl_exec;
    int mode;

    struct 
    {
        
        string project_dir;
        string fuzzer_dir;
        string corpus_dir;

        string queue_dir;
        string crash_queue_dir;
        string simulator_log_dir;
        string state_dump_model_dir;
    }dir_info;

    struct 
    {
        string config;
        string simulator_bin;
        string seed_file;
        string pool_file;
        string cov_log;
        string valid_bbl;
        string plot_log;
        string fuzzer_log;
        string mmio_model_file;
        string realtime_coverage_bin;
    }file_info;
    
    
};

static bool sort_queue(const queue_entry* l, const queue_entry* r) 
{
    return l->create_time < r->create_time;
}

void clean_fuzzer_shm(FuzzState *state);

#endif