#include <vector>
#include <map>
#include <poll.h>
#include <sched.h>
#include <stdint.h>
#include <cmath>
#include <stdlib.h>
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
#include <set>
#include <sys/wait.h>
#include <libgen.h>
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



FuzzState global_state;
bool terminate_next = false;

bool fuzz_one_post(FuzzState *state,Simulator *simulator);
void show_stat(FuzzState *state)
{
  char output[PATH_MAX];

  uint64_t time_fuzzed = (get_cur_time() / 1000) - state->start_time;
  uint64_t hour = time_fuzzed / 3600;
  uint64_t minutes = (time_fuzzed - hour * 3600) / 60;
  uint64_t seconds = time_fuzzed - hour * 3600 - minutes * 60;

  sprintf(output,"[%02lu:%02lu:%02lu] total exec %d bbl:%d paths:%lu used pool:%x timeout:%lu outofseed:%lu crash:%lu unique crash:%lu dbg_notfound:%lu bkp:%lu dbg:%lu intc:%lu yie:%lu ato:%lu\n",
  hour,
  minutes,
  seconds,
  state->total_exec,
  state->total_unique_bbls,
  state->entries->size(),
  state->shared_stream_used,
  state->exit_reason[EXIT_FUZZ_TIMEOUT],
  state->exit_reason[EXIT_FUZZ_OUTOF_STREAM],
  state->exit_reason[EXIT_FUZZ_CRASH],
  state->crashes->size(),
  state->exit_reason[EXIT_DBG_STREAM_NOTFOUND],
  state->exit_reason[EXIT_FUZZ_BKP],
  state->exit_reason[EXIT_FUZZ_EXCP_DEBUG],
  state->exit_reason[EXIT_FUZZ_EXCP_INTERRUPT],
  state->exit_reason[EXIT_FUZZ_EXCP_YIELD],
  state->exit_reason[EXIT_FUZZ_EXCP_ATOMIC]
  );
  
  fputs(output,stdout);
  fputs(output,state->flog);
}
void clean_fuzzer_shm(FuzzState *state)
{
  shmdt(state->shared_stream_data);
  shmctl(state->shm_id_streampool, IPC_RMID, 0);
}
void clean_fuzzer()
{
  show_stat(&global_state);
  
  if(global_state.mode == MODE_FUZZ)
  {
    rearrange_pool(&global_state);
    save_default_pool(&global_state,global_state.dir_info.queue_dir.c_str());
    save_queues(&global_state,global_state.dir_info.queue_dir.c_str());
  }
  clean_fuzzer_shm(&global_state);
}
void fuzzer_terminate(FuzzState *state) 
{
  wait_all_simualtor_finish_task(state);
  for(Simulator * simulator : (*state->simulators))
  {
    fuzz_terminate(simulator);
    wait_forkserver_terminate(simulator);
    kill_cleanup_simulator(&global_state,simulator->pid);
  }
  clean_fuzzer();
  exit(0);
}

void update_exit_info(FuzzState *state, EXIT_INFO *exit_info)
{
  state->total_unique_bbls = exit_info->unique_bbls;
  state->total_exec++;
  state->exit_reason[exit_info->exit_code]++;
}


void fuzzer_init(FuzzState *state, u32 coverage_size, u32 share_size) 
{
    char shm_str[PATH_MAX];
    state->map_size = coverage_size;
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

    state->total_unique_bbls = 0;
    state->start_time = get_cur_time() / 1000;

    state->use_fuzzware = true;
    state->mode = -1;
}



void save_coverage(FuzzState *state)
{
  FILE *f_coverage = fopen(state->file_info.realtime_coverage_bin.c_str(),"wb");
  fwrite(state->virgin_bits,state->map_size,1,f_coverage);
  fclose(f_coverage);
}


void init_fuzz(FuzzState *state)
{

  clean_queues(state->dir_info.queue_dir.c_str());
  clean_queues(state->dir_info.crash_queue_dir.c_str());
  add_irq_model(state);
  if(state->use_fuzzware)
    sync_models(state);

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
  printf("**********************init fuzz done**********************\n");

}

u64 get_fuzz_round_scale(u64 times)
{
  return times >> 6;
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
void trim_stream_data(FuzzState *state,queue_entry* fuzz_entry,u8 *new_bits,u32 size,set<u32> *fuzz_streams)
{
  if(!fuzz_streams)
    return;
  queue_entry* tmp_entry;
  Simulator *simulator;
  u32 trim_len;
  u32 trim_round;
  u32 new_len;
  input_stream* new_stream;
  input_stream* old_stream;
  set<u32> ids;


  u8 *bits = (u8 *)malloc(size);

  
  for(auto it = fuzz_streams->begin(); it != fuzz_streams->end(); it++)
  {
    old_stream = (*fuzz_entry->streams)[*it];
    trim_round = 1;
    new_len = old_stream->ptr->len;

    while(1)
    {
      trim_len = old_stream->ptr->len >> trim_round;
      if((trim_len < old_stream->ptr->element_size) || ((trim_len + old_stream->ptr->element_size) > new_len))
      {
        old_stream->ptr->len = new_len;
        break;
      }

      old_stream->ptr->len -= trim_len;
      EXIT_INFO exit_info = run_input(state,fuzz_entry,&simulator);
      get_new_bits(state->virgin_bits, simulator->trace_bits, size, bits);
      if (a_contains_b(bits,new_bits,size) && exit_info.exit_code == EXIT_FUZZ_OUTOF_STREAM)
      {
        // we can trim it
      }
      else
      {
        //otherwise we add the length back
        old_stream->ptr->len += trim_len;
      }
      trim_round++;
    }  
    
  }
  free(bits);
}
void trim_unused_stream_data(FuzzState *state,queue_entry* entry)
{
  int i;
  stream_metadata *stream;
  input_stream* new_stream;
  input_stream* old_stream;
  Simulator *simulator;

  run_input(state,entry,&simulator);

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

void trim_mutation(FuzzState *state,queue_entry* base_entry,queue_entry* fuzz_entry,set<u32> *fuzz_streams, u8 *new_bits,u32 size)
{
  if(!base_entry)
    return;
  
  set<u32> unused_mutations;
  queue_entry* tmp_entry;
  Simulator *simulator;

  tmp_entry = new_queue(state);
  copy_queue_streams(state,fuzz_entry,tmp_entry);

  u8 *bits = (u8 *)malloc(size);
  for (auto it = fuzz_streams->begin(); it != fuzz_streams->end(); it++)
  {
    replace_stream(state,tmp_entry,*it, (*base_entry->streams)[*it]);
    EXIT_INFO exit_info = run_input(state,tmp_entry,&simulator);
    get_new_bits(state->virgin_bits, simulator->trace_bits, simulator->map_size, bits);
    if (a_contains_b(bits,new_bits,size) && exit_info.exit_code == EXIT_FUZZ_OUTOF_STREAM)
    {
      unused_mutations.insert(*it);
    }
    else
    {
      replace_stream(state,tmp_entry,*it, (*fuzz_entry->streams)[*it]);      
    }
  }
  free_queue(state,tmp_entry);
  free(bits);
  for (u32 stream_id : unused_mutations)
  {
    fuzz_streams->erase(stream_id);
    replace_stream(state,fuzz_entry,stream_id, (*base_entry->streams)[stream_id]);
  }



}


void init_entry_state(FuzzState *state,queue_entry*q,queue_entry* base_entry, Simulator *simulator,u32 exit_reason)
{
  q->edges = count_trace_covered_bbl(simulator->trace_bits, simulator->map_size);
  q->fuzztimes = 0;
  q->cksum = hash32(simulator->trace_bits,simulator->map_size);
  q->exit_reason = exit_reason;
  q->priority = q->edges + 1;
  if(exit_reason != EXIT_FUZZ_OUTOF_STREAM)
    q->priority = 0;
  q->create_time = (get_cur_time() / 1000) - state->start_time;

  if(base_entry)
  {
    q->depth = base_entry->depth + 1;
  }
    
  else
  {
    q->depth = 1;
  }
    
}


void increase_schedule_times(FuzzState *state,set<u32> *fuzz_streams)
{
  for(auto it = fuzz_streams->begin(); it != fuzz_streams->end(); it++)
  {
    (*state->stream_schedule_info)[*it]->schedule_times ++;
  }
}
void increase_interesting_times(FuzzState *state,set<u32> *fuzz_streams)
{
  for(auto it = fuzz_streams->begin(); it != fuzz_streams->end(); it++)
  {
    (*state->stream_schedule_info)[*it]->interesting_times++;
  }
}

void calculate_stream_schedule_weight(FuzzState *state)
{
  if(!UR(20))
  {
    for(auto it = state->stream_schedule_info->begin(); it != state->stream_schedule_info->end(); it++)
    {
      it->second->weight = 1;
    }
  }
  else
  {
    for(auto it = state->stream_schedule_info->begin(); it != state->stream_schedule_info->end(); it++)
    {
      it->second->weight = (state->total_exec * it->second->interesting_times) / it->second->schedule_times;
      if(!it->second->weight)
        it->second->weight = 1;
    }
  }
}

bool fuzz_one_post(FuzzState *state,Simulator *simulator)
{
  queue_entry* base_entry = simulator->task.base_entry;
  queue_entry* fuzz_entry = simulator->task.fuzz_entry;
  set<u32> *fuzz_streams = simulator->task.fuzz_streams;

  assert((base_entry && fuzz_streams) || (!base_entry && !fuzz_streams));
  input_stream *new_stream;
  
  EXIT_INFO exit_info;
  if(simulator->status == STATUS_FREE)
    return true;
  


  while(1)
  {
    fuzz_exit(simulator,&exit_info);
    
    
    if(exit_info.exit_code == EXIT_FUZZ_STREAM_NOTFOUND)
    {
      
      if(state->models->find(exit_info.stream_info.exit_stream_id) == state->models->end())
      {
        if(state->use_fuzzware && state->models->size() <= MAX_FUZZWARE_MODEL)
        {
          run_modelling(state,exit_info.stream_info.exit_stream_id);
          sync_models(state);
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
        (*state->stream_schedule_info)[exit_info.stream_info.exit_stream_id]->interesting_times = 0;
        (*state->stream_schedule_info)[exit_info.stream_info.exit_stream_id]->weight = 1;
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
      kill_cleanup_simulator(state,simulator->pid);
      clean_fuzzer();
      exit(0);
      return true;
    }
    break;
  }
  
  
  update_exit_info(state, &exit_info);

  simulator_classify_count(simulator);
  int r = has_new_bits(state->virgin_bits, simulator->trace_bits, simulator->map_size);

  if(fuzz_streams)
    increase_schedule_times(state,fuzz_streams);

  if(unlikely(r && exit_info.exit_code != EXIT_FUZZ_CRASH))
  {
    u8 * new_bits = (u8 *)malloc(simulator->map_size);
    get_new_bits(state->virgin_bits, simulator->trace_bits, simulator->map_size, new_bits);
    trim_mutation(state,base_entry,fuzz_entry,fuzz_streams,new_bits,simulator->map_size);
    // trim_stream_data(state,fuzz_entry,new_bits,simulator->map_size,fuzz_streams);
    trim_unused_stream_data(state,fuzz_entry);
    if(fuzz_streams)
      increase_interesting_times(state,fuzz_streams);

    free(new_bits);

    Simulator *out_simulator;
    EXIT_INFO exit_info2 = run_input(state,fuzz_entry,&out_simulator);
    update_virgin(state->virgin_bits, out_simulator->trace_bits, out_simulator->map_size); 

    save_coverage(state);
    
    init_entry_state(state,fuzz_entry,base_entry, out_simulator,exit_info2.exit_code);

    insert_queue(state,fuzz_entry);

  }

  
  if(unlikely(exit_info.exit_code == EXIT_FUZZ_CRASH))
  {
    EXIT_INFO exit_info2 = run_input(state,fuzz_entry,0); // verify if it is really a crash
    if (likely(exit_info2.exit_code == EXIT_FUZZ_CRASH))
    {
      crash_info info;
      info.pc = exit_info2.exit_pc;
      info.lr = exit_info2.exit_lr;
      if(!find_crash(state, &info) && state->crashes->size() < 100)
      {
        insert_crash(state,info);
        init_entry_state(state,fuzz_entry,base_entry, simulator,exit_info.exit_code);
        save_crash(fuzz_entry,state->dir_info.crash_queue_dir.c_str());
        save_crash_pool(state,state->dir_info.crash_queue_dir.c_str(),fuzz_entry->cksum);
      }
    }
  }
  
  if(likely(!r || exit_info.exit_code == EXIT_FUZZ_CRASH))
  {
    free_queue(state,fuzz_entry);
  }

  if(likely(fuzz_streams))
    delete fuzz_streams;
  return true;
  
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
    priority = (*state->stream_schedule_info)[it->first]->weight;
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
  printf("avaliable stream not found\n");
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


  if (fuzz_entry->streams->size() <= 8)
  {
    use_stacking = (1 << (1 + UR(5)));   // afl ur(7) hoedur ur(5)
  }

  else if(fuzz_entry->streams->size() <= 32)
  {
    use_stacking = (1 << (1 + UR(6)));
  }
  else
  {
    use_stacking = (1 << (1 + UR(7)));
  }

  for(int i = 0; i < use_stacking; i++)
  {

    fuzz_stream_id =  select_stream(state,fuzz_entry,false);

    selected_streams->insert(fuzz_stream_id);

    fuzz_stream = havoc(state,(*fuzz_entry->streams)[fuzz_stream_id]);

    replace_stream(state,fuzz_entry,fuzz_stream_id,fuzz_stream);
    
  }

  if(!UR(5))
  {
    add_random(state, fuzz_entry);
  }

  simulator = get_avaliable_simulator(state);  
  
  fuzz_one_post(state,simulator);
  

  simulator_task(simulator,fuzz_entry,entry,selected_streams);
  fuzz_start(simulator);

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
    init_fuzz(state);
    int times = 0;
    
    while(1)
    {
        entry = select_entry(state);

        fuzz_queue(state,entry);

        if((times & 0xff) == 0)
        {
          show_stat(state);
        }
        if(times & 0xfff)
        {
          calculate_stream_schedule_weight(state);
        }
        if(terminate_next)
        {
          fuzzer_terminate(state);
        }
        
        if(get_stream_used(state) > (500 << 20))
        {
          wait_all_simualtor_finish_task(state);
          rearrange_pool(state);
        }

        
        times++;
            
    }
}

void fuzz_runonce(FuzzState *state)
{
  bool found_new = false;
  Simulator *simulator;
  load_default_pool(state,state->dir_info.queue_dir.c_str());
  load_queues(state,state->dir_info.queue_dir.c_str());
  std::sort(state->entries->begin(), state->entries->end(), sort_queue);

  FILE *f = fopen(state->file_info.plot_log.c_str(),"w");
  for(queue_entry *q : *state->entries)
  {
    EXIT_INFO exit_info = run_input(state,q,&simulator);
    
    if(exit_info.exit_code == EXIT_DBG_STREAM_NOTFOUND)
    {
      printf("pc %x queue %x not found stream %x\n",exit_info.exit_pc,q->cksum,exit_info.stream_info.exit_stream_id);
    }
    update_exit_info(state,&exit_info);
    if(f)
      fprintf(f,"%lu %d\n",q->create_time,state->total_unique_bbls);
    show_stat(state);
    if(terminate_next)
      fuzzer_terminate(state);
  }
  if(f)
    fclose(f);
}
void fuzz_run_oneseed(FuzzState *state)
{
  bool found_new = false;
  EXIT_INFO exit_info;
  Simulator *simulator;
  load_crash_pool(state,state->file_info.pool_file.c_str());
  queue_entry *q = load_queue(state,state->file_info.seed_file.c_str());
  exit_info = run_input(state,q,&simulator);
  update_exit_info(state, &exit_info);
  show_stat(state);
}


void init_dir(FuzzState *state)
{
  state->dir_info.project_dir = string(dirname(strdup(state->file_info.config.c_str())));
  state->dir_info.fuzzer_dir = state->dir_info.project_dir + "/aidfuzzer";
  if(state->file_info.valid_bbl == "")
  {
    state->file_info.valid_bbl = state->dir_info.project_dir + "/valid_basic_blocks.txt";
  }
  if(state->dir_info.corpus_dir == "")
  {
    state->dir_info.corpus_dir = state->dir_info.fuzzer_dir + "/corpus";
  }
  
  
  state->dir_info.queue_dir = state->dir_info.corpus_dir + "/queue/";
  state->dir_info.crash_queue_dir = state->dir_info.corpus_dir + "/crash/";

  state->dir_info.simulator_log_dir = state->dir_info.corpus_dir + "/log/";
  state->dir_info.state_dump_model_dir = state->dir_info.fuzzer_dir + "/model/";

  state->file_info.mmio_model_file = state->dir_info.state_dump_model_dir + MMIO_MODEL_FILENAME;
  state->file_info.realtime_coverage_bin = state->dir_info.corpus_dir + "/coverage.bin";

  mkdir(state->dir_info.fuzzer_dir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  mkdir(state->dir_info.corpus_dir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  mkdir(state->dir_info.queue_dir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  mkdir(state->dir_info.crash_queue_dir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  mkdir(state->dir_info.simulator_log_dir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  mkdir(state->dir_info.state_dump_model_dir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  
  state->flog = fopen((state->dir_info.corpus_dir + "/fuzzer.log").c_str(),"w");
  if(!state->flog)
    fatal("create fuzzer log file error\n");
}






void prepare_terminate(int signal)
{
  terminate_next = true;
  if(signal == SIGSEGV)
  {
    void* callstack[128];
    int frames = backtrace(callstack, 128);
    char** strs = backtrace_symbols(callstack, frames);

    puts("Stack Trace:");
    for (int i = 0; i < frames; ++i) 
    {
      puts(strs[i]);
    }
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
  int affinity = -1;
  int cores = 1;
  init();
  fuzzer_init(&global_state,FUZZ_COVERAGE_SIZE, SHARE_FUZZDATA_SIZE);

  auto fuzz_cli = ( 
    clipp::command("fuzz").set(global_state.mode,MODE_FUZZ),
    clipp::value("config",global_state.file_info.config),
    clipp::value("emulator",global_state.file_info.simulator_bin),

    clipp::option("-corpus")& clipp::value("corpus",global_state.dir_info.corpus_dir),
    clipp::option("-no_use_fuzzware").set(global_state.use_fuzzware,false),
    clipp::option("-core") & clipp::value("core",cores) ,
    clipp::option("-affinity") & clipp::value("affinity",affinity),
    clipp::option("-filter")& clipp::value("filter",global_state.file_info.valid_bbl)

  );
  auto run_cli = (
    clipp::command("run").set(global_state.mode,MODE_RUN),
    clipp::value("config",global_state.file_info.config),
    clipp::value("emulator",global_state.file_info.simulator_bin),
    
    clipp::option("-corpus")& clipp::value("corpus",global_state.dir_info.corpus_dir),
    clipp::option("-cov_log")& clipp::value("cov",global_state.file_info.cov_log),
    clipp::option("-filter")& clipp::value("filter",global_state.file_info.valid_bbl),
    clipp::option("-plot")& clipp::value("plot",global_state.file_info.plot_log)
    
  );
  auto debug_cli = (
    clipp::command("debug").set(global_state.mode,MODE_DEBUG),
    clipp::value("config",global_state.file_info.config),
    clipp::value("emulator",global_state.file_info.simulator_bin),

    clipp::value("pool",global_state.file_info.pool_file),
    clipp::value("queue",global_state.file_info.seed_file)
    
  );
  auto cli = ( 
    (fuzz_cli | run_cli | debug_cli)
  );

  if (!parse(argc, argv, cli))
  {
      puts("usage error");
      exit(0);
  }

    
  init_dir(&global_state);
  
  
  for(int i = 0; i < cores; i++)
  {
    allocate_new_simulator(&global_state,affinity);
  }
  if(global_state.mode == MODE_FUZZ)
  {
    fuzz_loop(&global_state);
  }
  else if(global_state.mode == MODE_RUN)
  {
    fuzz_runonce(&global_state);
  }

  else if(global_state.mode == MODE_DEBUG)
  {
    fuzz_run_oneseed(&global_state);
    
  }
  fuzzer_terminate(&global_state);
}

