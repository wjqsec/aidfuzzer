#include <vector>
#include <set>
#include <map>
#include <poll.h>
#include <sched.h>
#include <stdint.h>
#include <cmath>
#include <stdlib.h>
#include <stdio.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <string.h>
#include <algorithm>         /* Definition of AT_* constants */
#include <random>
#include <sys/syscall.h>      /* Definition of SYS_* constants */
#include <dirent.h>
#include <sys/time.h>
#include <iostream>
#include <iterator>
#include <sys/shm.h>
#include <clipp.h>
#include <fcntl.h>              /* Definition of O_* constants */
#include <sys/stat.h>
#include <execinfo.h>
#include <stdarg.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <sys/wait.h>
#include <linux/limits.h>
#include <time.h>
#include <stdio.h>
#include "fuzzer.h"
#include "mis_utl.h"
#include "iofuzzer.h"
#include "mutator.h"
#include "stream.h"
#include "queue_entry.h"
#include "simulator.h"
#include "model.h"
#include "stream_loader.h"
using namespace std;


void clean_fuzzer_shm(FuzzState *state);


FuzzState global_state;
bool terminate_next = false;


string project_dir;
char  in_dir[PATH_MAX];
char  out_dir[PATH_MAX];

char  queue_dir[PATH_MAX];
char  crash_dir[PATH_MAX];

char  log_dir[PATH_MAX];

char  config[PATH_MAX];

char  dump_dir[PATH_MAX];
char  dump_backup_dir[PATH_MAX];
char  model_dir[PATH_MAX];
char  model_file[PATH_MAX];
char  coverage_file[PATH_MAX];

string seed_file;
string pool_file;
string simulator_bin;
string cov_log;
string valid_bbl;

bool use_fuzzware = true;
bool model_infinite_loop = true;
int max_bbl_exec = MAX_BBL_EXEC;
int mode = -1;


void clean_fuzzer()
{
  show_stat(&global_state);
  
  if(mode == MODE_FUZZ)
  {
    save_coverage(&global_state);
    clean_queues(&global_state,queue_dir);
    save_default_pool(&global_state,queue_dir);
    save_queues(&global_state,queue_dir);
    save_freed_streams(&global_state,queue_dir);
  }
  
  

  clean_fuzzer_shm(&global_state);
}
void fuzzer_terminate(FuzzState *state) 
{
  for(Simulator * simulator : (*state->simulators))
  {
    fuzz_terminate(simulator);
    wait_forkserver_terminate(simulator);
    cleanup_simulator(&global_state,simulator->pid);
  }
  clean_fuzzer();
  exit(0);
}



void fuzzer_init(FuzzState *state, u32 max_edge, u32 share_size) 
{
    char shm_str[PATH_MAX];
    state->map_size = max_edge;
    state->share_size = share_size;
    state->virgin_bits = (u8*)malloc(state->map_size);
    memset(state->virgin_bits, 0xff, state->map_size);


    state->shm_id_streampool = shmget(IPC_PRIVATE, state->share_size, IPC_CREAT | IPC_EXCL |  0600);
    if (state->shm_id_streampool < 0) 
        fatal("shmget() failed");
    sprintf(shm_str,"%d",state->shm_id_streampool);
    setenv(SHM_SHARE_STREAM_VAR, shm_str, 1);
    state->shared_stream_data = (u8*)shmat(state->shm_id_streampool, NULL, 0);
    if (state->shared_stream_data == (void *)-1) 
        fatal("shmat() failed");

    
    state->total_exec = 0;
    state->total_queue_priority = 0;

    state->entries = new vector<queue_entry*>();
    state->models = new map<u32,input_model*>();
    state->simulators = new vector<Simulator*>();
    state->freed_streams = new map<u32,vector<input_stream*>*>();
    state->crashes = new vector<crash_info>();
    state->stream_schedule_info = new map<u32,stream_schedule_info *>();

    state->num_fds = 0;
    state->shared_stream_used = 0;

    state->start_time = get_cur_time() / 1000;

    sprintf(shm_str,"%s/fuzzer_log.txt",log_dir);
    state->flog = fopen(shm_str,"w");
    if(!state->flog)
      fatal("create fuzzer log file error\n");

}


void show_stat(FuzzState *state)
{
  char output[PATH_MAX];

  u32 edges = count_non_255_bytes(state->virgin_bits, state->map_size);
  sprintf(output,"[%lu] total exec %d bbl:%d paths:%lu used pool:%x timeout:%lu outofseed:%lu crash:%lu unique crash:%lu dbg_notfound:%lu\n",
  get_cur_time() / 1000,
  state->total_exec,
  edges,
  state->entries->size(),
  state->shared_stream_used,
  state->exit_reason[EXIT_FUZZ_TIMEOUT],
  state->exit_reason[EXIT_FUZZ_OUTOF_STREAM],
  state->exit_reason[EXIT_FUZZ_CRASH],
  state->crashes->size(),
  state->exit_reason[EXIT_DBG_STREAM_NOTFOUND]
  );
  
  fputs(output,stdout);
  fputs(output,global_state.flog);
  
  
}
void save_coverage(FuzzState *state)
{
  FILE *f_coverage = fopen(coverage_file,"wb");
  fwrite(state->virgin_bits,state->map_size,1,f_coverage);
  fclose(f_coverage);
}


void sync_state(FuzzState *state)
{


  Simulator *simulator;

  simulator = get_avaliable_simulator(state);
  queue_entry *q = new_queue(state);
  simulator_task(simulator,q,0,0);
  fuzz_start(simulator);
  fuzz_one_post(state,simulator);

  if(q->streams->size() == 0)
  {
    printf("fuzz init run cannot find stream, sth wrong\n");
    fuzzer_terminate(state);
  }
  
  if(state->entries->size() == 0)
  {
    printf("fuzz entry not found\n");
    fuzzer_terminate(state);
  }
  
  show_stat(state);
  printf("**********************sync state done**********************\n");

}

u32 run_input(FuzzState *state,queue_entry* fuzz_entry, int *r,Simulator **out_simulator)
{

  EXIT_INFO exit_info;
  Simulator *simulator;

  simulator = get_avaliable_simulator(state);  
  simulator_task(simulator,fuzz_entry,0,0);
  fuzz_start(simulator);
  fuzz_exit(simulator,&exit_info);
  simulator_classify_count(simulator);
  if(r)
    *r = has_new_bits(state->virgin_bits, simulator->trace_bits, simulator->map_size);
  if (out_simulator)
    *out_simulator = simulator;

  return exit_info.exit_code;
}

int get_fuzz_round_scale(u64 times)
{
  return times / 200;
  // if(times < 10000) 
  //   return 10;
  // if(times < 100000)
  //   return 100;
  // if(times < 1000000)
  //   return 1000;
  // if(times < 5000000)
  //   return 5000;
  // return 10000;
}
void trim_unused_stream_data(FuzzState *state,queue_entry* entry)
{
  int i;
  stream_metadata *stream;
  input_stream* new_stream;
  input_stream* old_stream;
  Simulator *simulator;

  run_input(state,entry, 0,&simulator);

  fuzz_queue *queue = (fuzz_queue *)simulator->shared_fuzz_queue_data;


  
  for(i = 0 ; i < queue->num_streams; i++)
  {
    stream = (stream_metadata*)(queue->streams[i].offset_to_stream_area + state->shared_stream_data);
    old_stream = (*entry->streams)[stream->stream_id];

    if(stream_shouldnot_mutate(old_stream))
      continue;
    else if (queue->streams[i].used == 0)
      remove_stream(state,entry,stream->stream_id);
    else if(old_stream->ptr->len > queue->streams[i].used)
    {
      new_stream = resize_stream(state,old_stream,queue->streams[i].used);
      
      replace_stream(state,entry,stream->stream_id, new_stream);
      
    }
  }

}

void trim_mutation(FuzzState *state,queue_entry* base_entry,queue_entry* fuzz_entry,set<u32> *fuzz_streams, u32 ck_sum)
{
  if(!base_entry)
    return;

  set<u32> unused_mutations;
  int r;
  queue_entry* tmp_entry;
  Simulator *simulator;

  tmp_entry = new_queue(state);

  copy_queue_streams(state,fuzz_entry,tmp_entry);
  for (auto it = fuzz_streams->begin(); it != fuzz_streams->end(); it++)
  {
    replace_stream(state,tmp_entry,*it, (*base_entry->streams)[*it]);
    u32 exit_code = run_input(state,tmp_entry, &r,&simulator);
    
    if (ck_sum == hash32(simulator->trace_bits,simulator->map_size))
    {
      unused_mutations.insert(*it);
    }
    else
    {
      replace_stream(state,tmp_entry,*it, (*fuzz_entry->streams)[*it]);      
    }
  }
  free_queue(state,tmp_entry);

  for (u32 stream_id : unused_mutations)
  {
    fuzz_streams->erase(stream_id);
    replace_stream(state,fuzz_entry,stream_id, (*base_entry->streams)[stream_id]);
  }



}


void init_entry_state(FuzzState *state,queue_entry*q, Simulator *simulator,u32 exit_reason)
{
  q->edges = count_bytes(simulator->trace_bits, simulator->map_size);
  q->fuzztimes = 0;
  q->cksum = hash32(simulator->trace_bits,simulator->map_size);
  q->exit_reason = exit_reason;
  q->priority = q->edges + 1;
  if(exit_reason == EXIT_FUZZ_TIMEOUT)
    q->priority = q->priority / 10 + 1;
  q->create_time = (get_cur_time() / 1000) - state->start_time;

  if(simulator->task.base_entry)
    q->depth = simulator->task.base_entry->depth + 1;
  else
    q->depth = 1;
}

void update_stream_schedule_info(FuzzState *state,set<u32> *fuzz_streams,int r)
{
  for(auto it = fuzz_streams->begin(); it != fuzz_streams->end(); it++)
  {
    (*state->stream_schedule_info)[*it]->schedule_times ++;
    if (unlikely(r)) 
    {
      // (*state->stream_schedule_info)[*it]->interesting_times += 100;
      // (*state->stream_schedule_info)[*it]->interesting_times += log10(state->total_exec) * 50;
      (*state->stream_schedule_info)[*it]->interesting_times += get_fuzz_round_scale(state->total_exec);
    }
     
    else
    {
      if((*state->stream_schedule_info)[*it]->interesting_times > 1)
        (*state->stream_schedule_info)[*it]->interesting_times--;
    } 
  }
}


bool fuzz_one_post(FuzzState *state,Simulator *simulator)
{
  bool ret;
  queue_entry* base_entry = simulator->task.base_entry;
  queue_entry* fuzz_entry = simulator->task.fuzz_entry;
  set<u32> *fuzz_streams = simulator->task.fuzz_streams;

  assert((base_entry && fuzz_streams) || (!base_entry && !fuzz_streams));
  input_stream *new_stream;
  
  EXIT_INFO exit_info;
  if(simulator->status == STATUS_FREE)
    return false;

  while(1)
  {
    fuzz_exit(simulator,&exit_info);
    
    if(exit_info.exit_code == EXIT_FUZZ_STREAM_NOTFOUND)
    {
      
      if(state->models->find(exit_info.stream_info.exit_stream_id) == state->models->end())
      {
        if(use_fuzzware)
        {
          run_modelling(state,simulator);
          sync_models(state,simulator);
        }
        if(state->models->find(exit_info.stream_info.exit_stream_id) == state->models->end())
        {
          add_default_model(state,exit_info.stream_info.exit_stream_id, exit_info.stream_info.mmio_len,exit_info.exit_pc,exit_info.stream_info.exit_mmio_addr);
        }
      }
      if (state->stream_schedule_info->find(exit_info.stream_info.exit_stream_id) == state->stream_schedule_info->end())
      {
        (*state->stream_schedule_info)[exit_info.stream_info.exit_stream_id] = new stream_schedule_info();
        (*state->stream_schedule_info)[exit_info.stream_info.exit_stream_id]->schedule_times = 1;
        (*state->stream_schedule_info)[exit_info.stream_info.exit_stream_id]->interesting_times = 1;
      }

      new_stream = allocate_enough_space_stream(state,exit_info.stream_info.exit_stream_id, 1 << 5);
      if(!stream_shouldnot_mutate(new_stream))
        rand_memset(new_stream->ptr->data,new_stream->ptr->len);

      insert_stream(state,fuzz_entry,new_stream);
      
      fuzz_continue_stream_notfound(simulator,new_stream);
      
      continue;
    }
    
    if(exit_info.exit_code == EXIT_CTL_TERMINATE)
    {
      cleanup_simulator(state,simulator->pid);
      clean_fuzzer();
      exit(0);
      return false;
    }
    break;
  }
  
  
    
  
  

  simulator_classify_count(simulator);
  int r = has_new_bits(state->virgin_bits, simulator->trace_bits, simulator->map_size);
  

  if(unlikely(r))
  {
    u32 ck_sum = hash32(simulator->trace_bits,simulator->map_size);
    trim_mutation(state,base_entry,fuzz_entry,fuzz_streams,ck_sum);

    trim_unused_stream_data(state,fuzz_entry);


    Simulator *out_simulator;
    u32 code = run_input(state,fuzz_entry,0,&out_simulator);
    r = has_new_bits_update_virgin(state->virgin_bits, out_simulator->trace_bits, out_simulator->map_size); 

    if(unlikely(r == 2)) 
      save_coverage(state);

    init_entry_state(state,fuzz_entry, out_simulator,code);

    

    insert_queue(state,fuzz_entry);

    ret = true;
  }
  if(fuzz_streams)
    update_stream_schedule_info(state,fuzz_streams,r);


  if(unlikely(exit_info.exit_code == EXIT_FUZZ_CRASH))
  {
    crash_info info;
    info.pc = exit_info.exit_pc;
    info.lr = exit_info.exit_lr;
    if(!find_crash(state, &info) && state->crashes->size() < 100)
    {

      insert_crash(state,info);
      save_crash(fuzz_entry,crash_dir);
      save_crash_pool(state,crash_dir,fuzz_entry->cksum);
    }

  }
  
  if(likely(!r))
  {
    free_queue(state,fuzz_entry);
    ret = false;
  }

  if(likely(fuzz_streams))
    delete fuzz_streams;
  return ret;
  
}

u32 select_stream(FuzzState *state,queue_entry* entry, bool uniformly)
{
  s64 total = 0;
  s64 priority;
  map<u32,s64> tmp_priority;
  for(auto it = entry->streams->begin(); it!= entry->streams->end(); it++)
  {
    
    if(stream_shouldnot_mutate(it->second))
      continue;

    priority = (*state->stream_schedule_info)[it->first]->interesting_times;
    total += priority;
    tmp_priority[it->first] = priority;

    
  }
 
  s32 random_number =  UR(total);
  s32 weight_sum = 0;
  for(auto it = tmp_priority.begin(); it!= tmp_priority.end(); it++)
  {
    weight_sum += it->second;
    if(random_number < weight_sum)
    {
      
      return it->first;
    }
  }
  
  return 0;
}

inline void fuzz_queue(FuzzState *state,queue_entry* entry)
{

  Simulator *simulator = NULL;
  input_stream *fuzz_stream;
  set<u32> *selected_streams;
  queue_entry* fuzz_entry;

  u32 use_stacking;
  u32 fuzz_stream_id = 0;
  
  entry->fuzztimes++;

  fuzz_entry = new_queue(state);
  selected_streams = new set<u32>();

  copy_queue_streams(state,entry,fuzz_entry);
 

  use_stacking = (1 << (1 + UR(4)));
  for(int i = 0; i < use_stacking; i++)
  {
    fuzz_stream_id =  select_stream(state,entry,false);

    selected_streams->insert(fuzz_stream_id);
    
    fuzz_stream = havoc(state,(*fuzz_entry->streams)[fuzz_stream_id]);

    replace_stream(state,fuzz_entry,fuzz_stream_id,fuzz_stream);
  }
  


  simulator = get_avaliable_simulator(state);  

  fuzz_one_post(state,simulator);

  simulator_task(simulator,fuzz_entry,entry,selected_streams);
  fuzz_start(simulator);

  if(terminate_next)
      fuzzer_terminate(state);

}

inline queue_entry* select_entry(FuzzState *state)
{
  static u32 last_num = 0;
  static u32 repeat_times = 0;

  if(UR(7))
  {
    if(last_num != state->entries->size())
    {
      repeat_times = 0x3ff;
      last_num = state->entries->size();
      return (*state->entries)[state->entries->size() - 1];
    }
    else if(repeat_times)
    {
      repeat_times--;
      return (*state->entries)[state->entries->size() - 1];
    }

    s32 random_number =  UR(state->total_queue_priority);
    s32 weight_sum = 0;
    
    for(int i = 0; i < state->entries->size(); i++)
    {
      weight_sum += (*state->entries)[i]->priority;
      if(random_number < weight_sum)
      {
        return (*state->entries)[i];
      }
    }
  }
  else
  {
    return (*state->entries)[UR(state->entries->size())];
  }
  
  fatal("select entry error\n");
  //not reachable

  return NULL;
} 


void fuzz_loop(FuzzState *state)
{ 
    queue_entry* entry;
    sync_state(state);
    int times = 0;
    while(1)
    {

        entry = select_entry(state);
        
        fuzz_queue(state,entry);
        
        
        
        if((times & 0xff) == 0)
        {
          show_stat(state);
          // dump_queue_schedule_info(state,entry);
        }
          
        
        times++;
            
    }
}

void fuzz_runonce(FuzzState *state)
{
  bool found_new = false;
  Simulator *simulator;
  EXIT_INFO exit_info;
  load_default_pool(state,queue_dir);
  load_queues(state,queue_dir);
  load_freed_streams(state,queue_dir);
  for(queue_entry *q : *state->entries)
  {
    simulator = get_avaliable_simulator(state);
    simulator_task(simulator,q,0,0);
    fuzz_start(simulator);
    fuzz_exit(simulator,&exit_info);
    if(exit_info.exit_code == EXIT_DBG_STREAM_NOTFOUND)
    {
      printf("pc %x queue %x not found stream %x\n",exit_info.exit_pc,q->cksum,exit_info.stream_info.exit_stream_id);
    }

    simulator_classify_count(simulator);
    has_new_bits_update_virgin(state->virgin_bits, simulator->trace_bits, simulator->map_size);
    show_stat(state);
  }
}
void fuzz_run_oneseed(FuzzState *state,const char *pool_file,const char *seed_file)
{
  bool found_new = false;
  EXIT_INFO exit_info;
  Simulator *simulator;
  load_crash_pool(state,pool_file);
  queue_entry *q = load_queue(&global_state,seed_file);
  simulator = get_avaliable_simulator(&global_state);
  simulator_task(simulator,q,0,0);
  fuzz_start(simulator);
  fuzz_exit(simulator,&exit_info);
  simulator_classify_count(simulator);
  has_new_bits_update_virgin(state->virgin_bits, simulator->trace_bits, simulator->map_size);
  show_stat(state);
}


void init_dir(void)
{
  sprintf(in_dir,"%s/in",project_dir.c_str());
  sprintf(out_dir,"%s/out",project_dir.c_str());
  sprintf(config,"%s/config.yml",project_dir.c_str());

  sprintf(queue_dir,"%s/",in_dir);
  sprintf(crash_dir,"%s/crash/",out_dir);
  sprintf(log_dir,"%s/log/",out_dir);
  sprintf(dump_dir,"%s/dump/",out_dir);
  sprintf(model_dir,"%s/model/",out_dir);
  sprintf(dump_backup_dir,"%s/dump_backup/",out_dir);
  sprintf(coverage_file,"%s/coverage.bin",out_dir);

  mkdir(in_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  mkdir(out_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  mkdir(queue_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  mkdir(crash_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  mkdir(log_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  mkdir(dump_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  mkdir(model_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  mkdir(dump_backup_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
}



void clean_fuzzer_shm(FuzzState *state)
{
  shmdt(state->shared_stream_data);
  shmctl(state->shm_id_streampool, IPC_RMID, 0);
}


void prepare_terminate(int signal)
{
  terminate_next = true;
  if(signal == SIGSEGV)
  {
    printf("segv\n");
    fuzzer_terminate(&global_state);
    exit(0);
    
  }
}

void init_signal_handler(void)
{
  if (signal(SIGINT, prepare_terminate) == SIG_ERR) 
  {
    printf("Error setting signal handler");
    exit(0);
  }
  if (signal(SIGSEGV, prepare_terminate) == SIG_ERR) 
  {
    printf("Error setting signal handler");
    
    exit(0);
  }
}

void init()
{
  init_signal_handler();
  simulator_env_init();
}
int main(int argc, char **argv)
{
  int status;
  Simulator *simulator;
  string mode_str;
  int opt;
  int cores = 1;
  init();

  auto fuzz_cli = ( 
    clipp::command("fuzz").set(mode,MODE_FUZZ),
    clipp::value("dir",project_dir),
    clipp::value("bin",simulator_bin),

    clipp::option("-no_use_fuzzware").set(use_fuzzware,false),
    clipp::option("-max_bbl")& clipp::value("max",max_bbl_exec),
    clipp::option("-core") & clipp::value("core",cores)
    
  );
  auto run_cli = (
    clipp::command("run").set(mode,MODE_RUN),
    clipp::value("dir",project_dir),
    clipp::value("bin",simulator_bin),
    
    clipp::option("-max_bbl")& clipp::value("max",max_bbl_exec),
    clipp::option("-cov_log")& clipp::value("cov",cov_log),
    clipp::option("-filter")& clipp::value("filter",valid_bbl)
  );
  auto debug_cli = (
    clipp::command("debug").set(mode,MODE_DEBUG),
    clipp::value("dir",project_dir),
    clipp::value("bin",simulator_bin),
    clipp::value("-queue",seed_file),
    clipp::value("-pool",pool_file)
  );
  auto cli = ( 
    (fuzz_cli | run_cli | debug_cli)
  );
  parse(argc, argv, cli);


  if(mode == MODE_DEBUG || mode == MODE_RUN)
  {
    cores = 1;
  }
    
  init_dir();
  printf("queue_dir:%s\n"
          "crash_dir:%s\n"
          "log_dir:%s\n"
          "dump_dir:%s\n"
          "dump_backup_dir:%s\n"
          "simulator_bin:%s\n"
          "cores:%d\n"
          "mode:%d\n"
          "config:%s\n",
          queue_dir,
          crash_dir,
          log_dir,
          dump_dir,
          dump_backup_dir,
          simulator_bin.c_str(),
          cores,
          mode,
          config);

  
  fuzzer_init(&global_state,FUZZ_COVERAGE_SIZE, SHARE_FUZZDATA_SIZE);
  
  for(int i = 0; i < cores; i++)
  {

    allocate_new_simulator(&global_state);

  }
  if(mode == MODE_FUZZ)
  {
    fuzz_loop(&global_state);
  }
  else if(mode == MODE_RUN)
  {
    fuzz_runonce(&global_state);
  }

  else if(mode == MODE_DEBUG)
  {
    fuzz_run_oneseed(&global_state, pool_file.c_str(), seed_file.c_str());
    
  }
  fuzzer_terminate(&global_state);
}

