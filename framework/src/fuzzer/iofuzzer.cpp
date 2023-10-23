#include <vector>
#include <set>
#include <map>
#include <poll.h>
#include <sched.h>
#include <stdint.h>
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
#include <sys/shm.h>
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

char *project_dir;
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

char *seed_file;
char *pool_file;
char *simulator_bin;
bool fresh_run;
bool model_systick = false;
bool use_fuzzware = true;
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
void fuzzer_terminate() 
{
  for(Simulator * simulator : *global_state.simulators)
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

    for(u64 i = 0 ; i < (state->share_size >> 2) ; i++)
      ((u32*)state->shared_stream_data)[i] = UR(0XFFFFFFFF);

    
    state->total_exec = 0;
    state->total_priority = 0;

    state->entries = new vector<queue_entry*>();
    state->models = new map<u32,input_model*>();
    state->streamid_mmioaddr_mapping = new map<u32,u32>();
    state->simulators = new vector<Simulator*>();
    state->freed_streams = new map<u32,vector<input_stream*>*>();
    state->crash_ids = new set<u32>();
    state->crashes = new vector<crash_info>();

    state->num_fds = 0;
    state->shared_stream_used = 0;


    sprintf(shm_str,"%s/fuzzer_log.txt",log_dir);
    state->flog = fopen(shm_str,"w");
    if(!state->flog)
      fatal("create fuzzer log file error\n");

}


void show_stat(FuzzState *state)
{
  char output[PATH_MAX];

  u32 edges = count_non_255_bytes(state->virgin_bits, state->map_size);
  sprintf(output,"[%lu] total exec %d bbl:%d paths:%lu used pool:%x timeout:%lu outofseed:%lu crash:%lu\n",
  get_cur_time() / 1000,
  state->total_exec,
  edges,
  state->entries->size(),
  state->shared_stream_used,
  state->exit_reason[EXIT_FUZZ_TIMEOUT],
  state->exit_reason[EXIT_FUZZ_OUTOF_STREAM],
  state->exit_reason[EXIT_FUZZ_CRASH]
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
  bool should_continue = false;
  bool found_new = false;
  Simulator *simulator;
  EXIT_INFO exit_info;
  u32 cksum;
  if(!fresh_run)
  {
    load_default_pool(state,queue_dir);
    load_queues(state,queue_dir);
    load_freed_streams(state,queue_dir);
  }
  

  if(state->entries->size() == 0)
  {
    simulator = get_avaliable_simulator(state);
    queue_entry *q = copy_queue(state,nullptr);
    simulator_task(simulator,q,0,0);
    fuzz_start(simulator);
    fuzz_one_post(state,simulator);
    if(q->streams->size() == 0)
    {
      printf("fuzz init run cannot find stream, sth wrong\n");
      fuzzer_terminate();
    }
  }
  else
  {
    for(queue_entry *q : *state->entries)
    {
      simulator = get_avaliable_simulator(state);
      simulator_task(simulator,q,0,0);
      fuzz_start(simulator);
      fuzz_exit(simulator,&exit_info);
      simulator_classify_count(simulator);
      has_new_bits_update_virgin(state->virgin_bits, simulator->trace_bits, simulator->map_size);
  
    }
  }
  if(state->entries->size() == 0)
  {
    printf("fuzz entry not found\n");
    fuzzer_terminate();
  }
  
  show_stat(state);
  printf("**********************sync state done**********************\n");

}



void trim_queue(FuzzState *state,queue_entry* entry,Simulator *simulator)
{
  int i;
  u32 id;
  u32 cksum;
  EXIT_INFO exit_info;
  stream_metadata *stream;


  simulator->fuzz_entry = entry;
  fuzz_queue *queue = (fuzz_queue *)simulator->shared_fuzz_queue_data;


  input_stream* new_stream;
  input_stream* old_stream;
  for(i = 0 ; i < queue->num_streams; i++)
  {
    stream = (stream_metadata*)(queue->streams[i].offset_to_stream_area + state->shared_stream_data);
    old_stream = (*entry->streams)[stream->stream_id];
    if(stream_shouldnot_mutate(old_stream))
      continue;

    if(queue->streams[i].used == 0)
    {
      remove_stream(state,entry,stream->stream_id);
    }
    else if(old_stream->ptr->len > queue->streams[i].used)
    {
      new_stream = decrease_stream(state,old_stream,queue->streams[i].used);

      replace_stream(state,entry,old_stream->ptr->stream_id, new_stream);
      
    }
  }

}

int get_fuzz_priority_increment(u64 fuzz_times)
{
  int ret = 0;

  if(fuzz_times < 100)
    ret = 10;
  else if(fuzz_times < 1000)
    ret = 50;
  else if(fuzz_times < 10000)
    ret = 100;
  else if(fuzz_times < 100000)
    ret = 300;
  else if(fuzz_times < 1000000)
    ret = 700;
  else if(fuzz_times < 10000000)
    ret = 20000;
  else
    ret = 50000;
  return ret;
}


void update_entry_state(queue_entry*q, Simulator *simulator,EXIT_INFO *exit_info)
{
  if(simulator->base_entry)
    q->depth = simulator->base_entry->depth + 1;
  else
    q->depth = 1;
  q->edges = count_bytes(simulator->trace_bits, simulator->map_size);
  q->cksum = hash32(simulator->trace_bits,simulator->map_size);
  q->exit_reason = exit_info->exit_code;
  q->priority = q->edges + 1;
  if(exit_info->exit_code == EXIT_FUZZ_TIMEOUT)
    q->priority = q->priority / 10 + 1;
}
void calculate_queue_totalstream_len(queue_entry*q)
{
  for(auto it = q->streams->begin(); it != q->streams->end(); it++)
  {
    if(stream_shouldnot_mutate(it->second))
      continue;
    
    q->total_stream_len += it->second->ptr->len;
  }
}
void update_quque_runtime_stream_priority(queue_entry*q, set<input_stream*> *fuzz_streams, int diff)
{
  if(!fuzz_streams || !q)
    return;
  for(auto it = fuzz_streams->begin(); it != fuzz_streams->end(); it++)
  {
    s32* tmp = &(*q->runtime_stream_priority)[(*it)->ptr->stream_id];
    *tmp += diff;
    if(*tmp <= 0)
      *tmp = 1;
  }
}
bool fuzz_one_post(FuzzState *state,Simulator *simulator)
{
  bool ret;
  queue_entry* base_entry = simulator->base_entry;
  queue_entry* fuzz_entry = simulator->fuzz_entry;
  set<input_stream*> *fuzz_streams = simulator->fuzz_streams;;

  input_stream *outofseed_stream;
  input_stream *new_stream;
  
  EXIT_INFO exit_info;
  if(simulator->status == STATUS_FREE)
    return false;

  while(1)
  {
    fuzz_exit(simulator,&exit_info);
    
    if(exit_info.exit_code == EXIT_FUZZ_STREAM_NOTFOUND)
    {

      if(exit_info.stream_dumped == 0)
      {
        if(use_fuzzware)
        {
          run_modelling(state,simulator);
          sync_models(state,simulator);
        }
        else
        {
          add_default_model(state,exit_info.exit_stream_id, exit_info.mmio_len);
        }
      }

      new_stream = allocate_enough_space_stream(state,exit_info.exit_stream_id, DEFAULT_STREAM_LEN);

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
  
  if(base_entry)
    base_entry->fuzztimes++;
  
  simulator_classify_count(simulator);
  int r = has_new_bits_update_virgin(state->virgin_bits, simulator->trace_bits, simulator->map_size);

  if(exit_info.exit_code == EXIT_FUZZ_CRASH)
  {
    crash_info info;
    info.pc = exit_info.exit_pc;
    info.lr = exit_info.exit_lr;
    if(!find_crash(state, &info))
    {
      insert_crash(state,info);
      update_entry_state(fuzz_entry, simulator,&exit_info);
      save_crash(fuzz_entry,crash_dir);
      save_crash_pool(state,crash_dir,fuzz_entry->cksum);

    }

  }

  
  
  if(unlikely(r))
  {
    if(unlikely(r == 2))
      save_coverage(state);

    update_entry_state(fuzz_entry, simulator,&exit_info);

    
    trim_queue(state,fuzz_entry,simulator);

    
    calculate_queue_totalstream_len(fuzz_entry);
    
    update_quque_runtime_stream_priority(base_entry, fuzz_streams, get_fuzz_priority_increment(state->total_exec));
     
    insert_queue(state,fuzz_entry);

    ret = true;
  }
  else
  {
    update_quque_runtime_stream_priority(base_entry, fuzz_streams,-1);
    free_queue(state,fuzz_entry);
    ret = false;
  }
  if(fuzz_streams)
    delete fuzz_streams;
  return ret;
  
}



inline input_stream* select_stream(queue_entry *q, bool use_extra_priority,  u64 total)
{
  s32 random_number =  UR(total);
  s32 weight_sum = 0;
  for(auto it = q->streams->begin() ; it != q->streams->end() ; it++)
  {
    if(stream_shouldnot_mutate(it->second))
        continue;
    if(use_extra_priority)
      weight_sum += it->second->ptr->len * it->second->priority;
    else
      weight_sum += it->second->ptr->len;
    if(random_number < weight_sum)
    {
      return it->second;
    }
  }
  return nullptr;
}
inline void select_streams_2(queue_entry *q,set<input_stream*>* ret)
{
  

  input_stream* stream;
  do {
    for(auto it = q->runtime_stream_priority->begin() ; it != q->runtime_stream_priority->end(); it++)
    {
      stream = (*q->streams)[it->first];
      if(stream_shouldnot_mutate(stream))
        continue;
      
      if((it->second) > 10)
      {
        ret->insert(stream);
      }
      else
      {
        if(!UR(10))
        {
          ret->insert(stream);
        }
          
      }
    }
  } while(ret->size() == 0 );
}
inline set<input_stream*>* select_streams(queue_entry *q)
{

  
  set<input_stream*>* ret = new set<input_stream*>();
  input_stream* tmp;
  u32 use_stacking;
  u64 total_with_extra_priority = 0;
  int i;
  

  use_stacking = (1 << (1 + UR(5)));


  if(UR(5))
  {
    
    for(i = 0; i < use_stacking; i++)
    {
      tmp = select_stream(q,false,q->total_stream_len);
      if(tmp)
        ret->insert(tmp);
    }
  }
  else
  {
    if(UR(3))
    {
      select_streams_2(q,ret);
    }
    else
    {

      for(auto it = q->streams->begin(); it!= q->streams->end(); it++)
      {
        if(it->second->ptr->len <= 0x20)
          ret->insert(it->second);
      }

    }
    
  }

  
  return ret;
}

inline void fuzz_queue(FuzzState *state,queue_entry* entry)
{
  
  Simulator *simulator = NULL;
  input_stream *fuzz_stream;
  set<input_stream*> *selected_streams;
  queue_entry* fuzz_entry;


  fuzz_entry = copy_queue(state,entry);


  selected_streams = select_streams(entry);

  for(auto it = selected_streams->begin(); it != selected_streams->end(); it++) 
  {

    fuzz_stream = havoc(state,*it);

    replace_stream(state,fuzz_entry,(*it)->ptr->stream_id,fuzz_stream);

    
  }

  simulator = get_avaliable_simulator(state);  
  fuzz_one_post(state,simulator);
  simulator_task(simulator,fuzz_entry,entry,selected_streams);
  
  fuzz_start(simulator);
  
  if(terminate_next)
      fuzzer_terminate();
  

}


inline queue_entry* select_entry(FuzzState *state)
{
  static u32 last_num = 0;
  if(last_num != state->entries->size())
  {
    last_num = state->entries->size();
    return (*state->entries)[state->entries->size() - 1];
  }
  last_num = state->entries->size();   

  s32 random_number =  UR(state->total_priority);
  s32 weight_sum = 0;
  
  for(int i = 0; i < state->entries->size(); i++)
  {
    weight_sum += (*state->entries)[i]->priority;
    if(random_number < weight_sum)
    {
      return (*state->entries)[i];
    }
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
          show_stat(state);
        
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
    simulator_classify_count(simulator);
    has_new_bits_update_virgin(state->virgin_bits, simulator->trace_bits, simulator->map_size);
    show_stat(state);
  }
}
void fuzz_run_oneseed(FuzzState *state, char *pool_file, char *seed_file)
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
}


void init_dir(void)
{
  sprintf(in_dir,"%s/in",project_dir);
  sprintf(out_dir,"%s/out",project_dir);
  sprintf(config,"%s/config.yml",project_dir);

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
  EXIT_INFO exit_info;
  
  int opt;
  int cores;
  init();
  while ((opt = getopt(argc, argv, "d:m:p:e:s:ftnb:")) != -1) 
  {
      switch (opt) {
      case 'm':
          if(strcmp(optarg, "fuzz") == 0)
            mode = MODE_FUZZ;
          if(strcmp(optarg, "debug") == 0)
            mode = MODE_DEBUG;
          if(strcmp(optarg, "run") == 0)
            mode = MODE_RUN;
          break;
      case 'e':
          cores = atoi(optarg);
          break;
      case 'd':
          project_dir = optarg;
          break;
      case 'p':
          pool_file = optarg;
          break;
      case 's':
          seed_file = optarg;
          break;
      case 'f':
          fresh_run = true;
          break;
      case 't':
          model_systick = true;
          break;
      case 'n':
          use_fuzzware = false;
          break;
      case 'b':
          max_bbl_exec = atoi(optarg);
          break;
          
      default: /* '?' */
          printf("Usage error\n");
          exit(0);
      }
  }
  if(mode == MODE_DEBUG || mode == MODE_RUN)
  {
    cores = 1;
    fresh_run = false;
  }
    
  
  simulator_bin = argv[optind];
  init_dir();
  printf("queue_dir:%s\n"
          "crash_dir:%s\n"
          "log_dir:%s\n"
          "dump_dir:%s\n"
          "dump_backup_dir:%s\n"
          "simulator_bin:%s\n"
          "cores:%d\n"
          "mode:%d\n"
          "config:%s\n"
          "model_systick:%d\n"
          "fresh_run:%d\n",
          queue_dir,
          crash_dir,
          log_dir,
          dump_dir,
          dump_backup_dir,
          simulator_bin,
          cores,
          mode,
          config,
          model_systick,
          fresh_run);

  
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
    fuzz_run_oneseed(&global_state, pool_file, seed_file);
    
  }
  fuzzer_terminate();
}

