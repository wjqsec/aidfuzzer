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
void clean_simualtor_shm(Simulator * simulator);
void sync_models(FuzzState *state,Simulator *simulator);

FuzzState global_state;
bool terminate_next = false;


char  *in_dir;
char  *out_dir;

char *simulator_bin;

char  queue_dir[PATH_MAX];
char  crash_dir[PATH_MAX];

char  log_dir[PATH_MAX];

char *config;

char  dump_dir[PATH_MAX];
char  dump_backup_dir[PATH_MAX];
char  model_dir[PATH_MAX];
char  model_file[PATH_MAX];
char  coverage_file[PATH_MAX];

char *seed_file;

bool fresh_run;


void kill_simulator(Simulator * simulator)
{
  int status;
  kill(simulator->pid,SIGKILL);
  waitpid(simulator->pid,&status,WEXITED | WSTOPPED);
  printf("simualtor pid:%d terminate\n",simulator->pid);
  simulator->status = STATUS_KILLED;
}

void cleanup_simulator(int pid)
{
  int status;
  for(Simulator * simulator : *global_state.simulators)
  {
    if(simulator->pid != pid)
      continue;
    kill_simulator(simulator);
    clean_simualtor_shm(simulator);
  }

}
void clean_fuzzer()
{
  show_stat(&global_state);
  save_pool(&global_state,queue_dir);
  save_queues(&global_state,queue_dir);
  save_freed_streams(&global_state,queue_dir);
  clean_fuzzer_shm(&global_state);
}
void fuzzer_terminate() 
{
  for(Simulator * simulator : *global_state.simulators)
  {
    fuzz_terminate(simulator);
    wait_forkserver_terminate(simulator);
    cleanup_simulator(simulator->pid);
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

    state->num_fds = 0;
    state->shared_stream_used = 0;


    sprintf(shm_str,"%s/fuzzer_log.txt",log_dir);
    state->flog = fopen(shm_str,"w");
    if(!state->flog)
      fatal("create fuzzer log file error\n");

}


void allocate_new_simulator(FuzzState *state)
{
  static int start_fd = 100;
  static int cpu = 0;
  int status;
  int i;
  pid_t pid;
  int st_pipe[2], ctl_pipe[2];
  char shm_str[PATH_MAX];
  EXIT_INFO exit_info;

  Simulator *simulator = new Simulator();
  simulator->state = state;
  simulator->map_size = state->map_size;
  simulator->status = STATUS_FREE;
  simulator->id_queue_idx_mapping = new map<u32,int>();

  simulator->shm_id_trace_bit = shmget(IPC_PRIVATE, simulator->map_size, IPC_CREAT | IPC_EXCL | 0600);
  if (simulator->shm_id_trace_bit < 0) 
      fatal("shmget() failed");
  sprintf(shm_str,"%d",simulator->shm_id_trace_bit);
  setenv(SHM_ENV_VAR, shm_str, 1);
  simulator->trace_bits = (u8*)shmat(simulator->shm_id_trace_bit, NULL, 0);
  if (simulator->trace_bits == (void *)-1) 
      fatal("shmat() failed");
  memset(simulator->trace_bits,0,simulator->map_size);

  simulator->shm_id_fuzz_queue = shmget(IPC_PRIVATE, 0x1000, IPC_CREAT | IPC_EXCL | 0600);
  if (simulator->shm_id_fuzz_queue < 0) 
      fatal("shmget() failed");
  sprintf(shm_str,"%d",simulator->shm_id_fuzz_queue);
  setenv(SHM_SHARE_FUZZ_QUEUE_VAR, shm_str, 1);
  simulator->shared_fuzz_queue_data = (u8*)shmat(simulator->shm_id_fuzz_queue, NULL, 0);
  if (simulator->shared_fuzz_queue_data == (void *)-1) 
      fatal("shmat() failed");

  if (pipe(st_pipe) || pipe(ctl_pipe)) fatal("pipe() failed");
  if (dup2(ctl_pipe[0], start_fd) < 0) fatal("dup2() failed");
  if (dup2(st_pipe[1], start_fd + 1) < 0) fatal("dup2() failed");

  
  simulator->fd_ctl_to_simulator = ctl_pipe[1];
  simulator->fd_ctl_from_simulator = st_pipe[0];

  state->fds[state->num_fds].fd = simulator->fd_ctl_from_simulator;
  state->fds[state->num_fds].events = POLLIN;
  state->fds[state->num_fds].revents = 0;
  
	char *child_arg[1000];
  i = 0;
  child_arg[i++] = simulator_bin;

  simulator->simulator_dump_dir = alloc_printf("%s/simulator_%d",dump_dir,cpu);
  simulator->simulator_model_dir =  alloc_printf("%s/simulator_%d",model_dir,cpu);
  simulator->simulator_log_dir = alloc_printf("%s/simulator_%d",log_dir,cpu);
  mkdir(simulator->simulator_dump_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  mkdir(simulator->simulator_model_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  mkdir(simulator->simulator_log_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

  child_arg[i++] = (char*)"-d";
  child_arg[i++] =  simulator->simulator_dump_dir;
  child_arg[i++] = (char*)"-m";
  child_arg[i++] = simulator->simulator_model_dir;
  child_arg[i++] = (char*)"-l";
  child_arg[i++] = simulator->simulator_log_dir;
  child_arg[i++] = (char*)"-f";
  child_arg[i++] = alloc_printf("%d",start_fd);
  child_arg[i++] = (char*)"-t";
  child_arg[i++] = alloc_printf("%d",start_fd + 1);
  child_arg[i++] = (char*)"-c";
  child_arg[i++] =  config;
  child_arg[i++] = NULL;

  pid = fork();
	if (pid < 0) fatal("fork error\n");
	else if(!pid)
	{

		execv(child_arg[0],child_arg);
	}
  simulator->pid = pid;
  simulator->cpu = cpu;
  simulator->status = STATUS_FREE;

  state->simulators->push_back(simulator);

  printf("pid:%d wait for fork server\n",simulator->pid);
      

  fuzz_exit(simulator,&exit_info);

  if(exit_info.exit_code != EXIT_FORKSRV_UP)
  {
    cleanup_simulator(pid);
    clean_fuzzer_shm(state);
    exit(0);
  }
  printf("pid:%d fork server is up\n",simulator->pid);
  simulator_classify_count(simulator);
  has_new_bits_update_virgin(state->virgin_bits, simulator->trace_bits, simulator->map_size);
  sync_models(state,simulator);
  
  start_fd += 2;
  cpu++;
  state->num_fds++;
}





void show_stat(FuzzState *state)
{
  char output[PATH_MAX];

  u32 edges = count_non_255_bytes(state->virgin_bits, state->map_size);
  sprintf(output,"[%lu] total exec %d edges:%d paths:%lu used pool:%x none:%lu timeout:%lu outofseed:%lu crash:%lu\n",
  get_cur_time() / 1000,
  state->total_exec,
  edges,
  state->entries->size(),
  state->shared_stream_used,
  state->exit_reason[EXIT_STREAM_NOTFOUND],
  state->exit_reason[EXIT_TIMEOUT],
  state->exit_reason[EXIT_OUTOF_STREAM],
  state->exit_reason[EXIT_CRASH]
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
  Simulator *simulator;
  EXIT_INFO exit_info;
  u32 cksum;
  if(!fresh_run)
  {
    load_pool(state,queue_dir);
    load_queues(state,queue_dir);
    load_freed_streams(state,queue_dir);
  }
  

  if(state->entries->size() == 0)
  {
    simulator = get_avaliable_simulator(state);
    queue_entry *q = copy_queue(state,nullptr);
    simulator_task(simulator,q,0, 0);
    fuzz_start(simulator);
    fuzz_one_post(state,simulator);
  }
  // else
  // {
  //   for(queue_entry *q : *state->entries)
  //   {
  //     simulator = get_avaliable_simulator(state);
  //     simulator->fuzz_entry = q;
  //     fuzz_start(simulator);
  //     fuzz_exit(simulator,&exit_info);
  //     simulator_classify_count(simulator);
  //     has_new_bits_update_virgin(state->virgin_bits, simulator->trace_bits, simulator->map_size);
  //   }
  // }
  if(state->entries->size() == 0)
  {
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
    if(old_stream->ptr->mode == MODEL_CONSTANT || old_stream->ptr->mode == MODEL_PASSTHROUGH)
      continue;

    if(old_stream->ptr->len > queue->streams[i].used)
    {
      new_stream = decrease_stream(state,old_stream,queue->streams[i].used);
      replace_stream(state,entry,old_stream, new_stream);
    }
  }

}

int get_fuzz_priority_increament(u64 fuzz_times)
{
  int ret = 0;

  if(fuzz_times < 100)
    ret = 5;
  else if(fuzz_times < 1000)
    ret = 10;
  else if(fuzz_times < 10000)
    ret = 20;
  else if(fuzz_times < 100000)
    ret = 100;
  else
    ret = 5000;
  return ret;
}
void fuzz_one_post(FuzzState *state,Simulator *simulator)
{
  queue_entry* base_entry;
  queue_entry* fuzz_entry;
  input_stream *fuzz_stream = nullptr;

  input_stream *outofseed_stream;
  input_stream *new_stream;
  
  EXIT_INFO exit_info;

  fuzz_entry = simulator->fuzz_entry;
  while(1)
  {
    fuzz_exit(simulator,&exit_info);
    if(exit_info.exit_code == EXIT_CRASH)
    {
      simulator_classify_count(simulator);
      u32 cksum = hash32(simulator->trace_bits,simulator->map_size);
      if(state->crash_ids->find(cksum) != state->crash_ids->end())
      {
        free_queue(state,fuzz_entry);
        return;
      }

      state->crash_ids->insert(cksum);
      fuzz_entry->cksum = cksum;
      save_crash(fuzz_entry,crash_dir);

      return;
    }

    if(exit_info.exit_code == EXIT_STREAM_NOTFOUND)
    {

      if(exit_info.stream_dumped == 0)
      {

        run_modelling(state,simulator);

        sync_models(state,simulator);
        // add_new_stream_for_all_queue(state,exit_info.exit_stream_id);
      }

      new_stream = allocate_enough_space_stream(state,exit_info.exit_stream_id, DEFAULT_STREAM_LEN);

      insert_stream(state,fuzz_entry,new_stream);

      fuzz_continue_stream_notfound(simulator,new_stream);

      continue;
    }
    if(exit_info.exit_code == EXIT_NOTENOUGHT_STREAM)
    {
      outofseed_stream = (*fuzz_entry->streams)[exit_info.exit_stream_id];
      new_stream = extend_stream(state,outofseed_stream,DEFAULT_STREAM_LEN);
      replace_stream(state,fuzz_entry,outofseed_stream, new_stream);
      fuzz_continue_stream_outof(simulator,new_stream);
      continue;
    }
    if(exit_info.exit_code == EXIT_TERMINATE)
    {
      cleanup_simulator(simulator->pid);
      clean_fuzzer();
      exit(0);
      return;
    }
    break;
  }
  
  
  simulator_classify_count(simulator);
  int r = has_new_bits_update_virgin(state->virgin_bits, simulator->trace_bits, simulator->map_size);
  base_entry = simulator->base_entry;
  if(base_entry)
  {
    base_entry->fuzztimes++;
    fuzz_stream = (*base_entry->streams)[simulator->fuzz_stream_id];
  }
    
  
  if(unlikely(r))
  {
    if(unlikely(r == 2))
      save_coverage(state);
    if(fuzz_stream)
      fuzz_stream->priority += get_fuzz_priority_increament(base_entry->fuzztimes);
    fuzz_entry->depth++;
    fuzz_entry->edges = count_bytes(simulator->trace_bits, simulator->map_size);
    fuzz_entry->cksum = hash32(simulator->trace_bits,simulator->map_size);
    
    fuzz_entry->priority = fuzz_entry->edges + 1;
    if(exit_info.exit_code == EXIT_TIMEOUT)
      fuzz_entry->priority = fuzz_entry->priority / 10 + 1;
    trim_queue(state,fuzz_entry,simulator);
    insert_queue(state,fuzz_entry);
  }
  else
  {
    free_queue(state,fuzz_entry);
    if(fuzz_stream && fuzz_stream->priority > 1)
    {
      fuzz_stream->priority-- ;
    }
  }

  
}





inline void fuzz_queue(FuzzState *state,queue_entry* entry)
{
  bool should_continue = false;
  s32 i;
  Simulator *simulator = NULL;
  input_stream *fuzz_stream;
  queue_entry* fuzz_entry;
  s32 priority;

  for(auto it = entry->streams->begin() ; it != entry->streams->end() ; it++)
  {
    if(it->second->ptr->mode == MODEL_CONSTANT || it->second->ptr->mode == MODEL_PASSTHROUGH || it->second->ptr->len == 0)
      continue;

    priority = it->second->priority;
    
    for(i = 0 ; i < priority ; i++)
    {
      simulator = get_avaliable_simulator(state);  
      fuzz_entry = copy_queue(state,entry);
      fuzz_stream = havoc(state,it->second);
      replace_stream(state,fuzz_entry,it->second, fuzz_stream);
      simulator_task(simulator,fuzz_entry,entry, it->second->ptr->stream_id);
      fuzz_start(simulator);

      if(terminate_next)
          fuzzer_terminate();
      
    } 
    show_stat(state);
  }
  if(terminate_next)
          fuzzer_terminate();
  

}


inline queue_entry* select_entry(FuzzState *state)
{
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
    int round = 0;
    while(1)
    {
        entry = select_entry(state);
        fuzz_queue(state,entry);
        
        round++;
            
    }
}



void init_dir(void)
{

  sprintf(queue_dir,"%s",in_dir);
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


void clean_simualtor_shm(Simulator * simulator)
{

  shmdt(simulator->trace_bits);
  shmdt(simulator->shared_fuzz_queue_data);

  shmctl(simulator->shm_id_trace_bit, IPC_RMID, 0);
  shmctl(simulator->shm_id_fuzz_queue, IPC_RMID, 0);
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
int main(int argc, char **argv)
{
  int status;
  Simulator *simulator;
  EXIT_INFO exit_info;
  int mode = -1;
  int opt;
  int cores;
  init_signal_handler();
  simulator_env_init();
  while ((opt = getopt(argc, argv, "m:i:o:c:e:s:f")) != -1) 
  {
      switch (opt) {
      case 'm':
          if(strcmp(optarg, "fuzz") == 0)
            mode = MODE_FUZZ;
          if(strcmp(optarg, "debug") == 0)
            mode = MODE_DEBUG;
          break;
      case 'i':
          in_dir = optarg;
          break;
      case 'o':
          out_dir = optarg;
          break;
      case 'e':
          cores = atoi(optarg);
          break;
      case 'c':
          config = optarg;
          break;
      case 's':
          seed_file = optarg;
          break;
      case 'f':
          fresh_run = true;
          break;
      default: /* '?' */
          printf("Usage error\n");
          exit(0);
      }
  }
  if(mode == MODE_DEBUG)
    cores = 1;
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
  else if(mode == MODE_DEBUG)
  {
    load_pool(&global_state,queue_dir);
    queue_entry *q = load_queue(&global_state,seed_file);
    simulator = get_avaliable_simulator(&global_state);
    simulator_task(simulator,q,0, 0);
    for(int i = 0; i < 10;i++)
    {
      fuzz_start(simulator);
      fuzz_exit(simulator,&exit_info);
    }
  }
  fuzzer_terminate();
}

