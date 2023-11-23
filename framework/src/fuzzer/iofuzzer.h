#ifndef IOFUZZER_INCLUDED
#define IOFUZZER_INCLUDED

#include <map>
#include <vector>
#include <set>
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

    char *simulator_dump_dir;
    char *simulator_model_dir;
    char *simulator_log_dir;

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
 
};




bool fuzz_one_post(FuzzState *state,Simulator *simulator);
void show_stat(FuzzState *state);
void save_coverage(FuzzState *state);
void clean_fuzzer_shm(FuzzState *state);



extern bool terminate_next;

extern char *project_dir;
extern char  in_dir[PATH_MAX];
extern char  out_dir[PATH_MAX];

extern char  queue_dir[PATH_MAX];
extern char  crash_dir[PATH_MAX];

extern char  log_dir[PATH_MAX];

extern char  config[PATH_MAX];

extern char  dump_dir[PATH_MAX];
extern char  dump_backup_dir[PATH_MAX];
extern char  model_dir[PATH_MAX];
extern char  model_file[PATH_MAX];
extern char  coverage_file[PATH_MAX];

extern char *seed_file;
extern char *pool_file;
extern char *simulator_bin;
extern bool fresh_run;
extern bool model_systick;
extern bool use_fuzzware;
extern int max_bbl_exec;
extern int mode;

extern bool model_infinite_loop;
#endif