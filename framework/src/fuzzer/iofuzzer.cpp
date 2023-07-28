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
#include "fuzzer.h"
#include "afl_utl.h"
#include "iofuzzer.h"
#include "mutator.h"
#include "stream.h"
using namespace std;





FuzzState global_state;



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








inline void insert_queue(FuzzState *state,queue_entry* q)
{
  u32 id;
  state->entries->push_back(q);
  state->total_priority += q->priority;
  vector<input_stream *> *queue_streams;
  for (auto it = q->streams->begin(); it != q->streams->end(); it++)
  {
    id = it->first;
    if(state->all_queued_streams->count(id) == 0)
    {
      (*state->all_queued_streams)[id] = new vector<input_stream *>();
    }
    queue_streams = (*state->all_queued_streams)[id];
    queue_streams->push_back(it->second);
  }
  
}
inline queue_entry* copy_queue(FuzzState *state,queue_entry* q)
{
  queue_entry *entry = new queue_entry();
  entry->depth = 1;
  entry->priority = DEFAULT_QUEUE_PRIORITY;
  entry->streams = new map<u32,input_stream*>();
  if(q)
  {
    entry->streams->insert(q->streams->begin(), q->streams->end());
    entry->depth = q->depth;
  }
  return entry;
}



void fuzzer_init(FuzzState *state, u32 map_size, u32 share_size) 
{
    char shm_str[PATH_MAX];
    s32 shm_id;
    state->map_size = map_size;
    state->share_size = share_size;
    state->virgin_bits = (u8*)malloc(state->map_size);
    memset(state->virgin_bits, 0xff, state->map_size);


    shm_id = shmget(IPC_PRIVATE, state->share_size, IPC_CREAT | IPC_EXCL | 0600);
    if (shm_id < 0) 
        fatal("shmget() failed");
    sprintf(shm_str,"%d",shm_id);
    setenv(SHM_SHARE_STREAM_VAR, shm_str, 1);
    state->shared_stream_data = (u8*)shmat(shm_id, NULL, 0);
    if (state->shared_stream_data == (void *)-1) 
        fatal("shmat() failed");

    for(u64 i = 0 ; i < (state->share_size >> 2) ; i++)
      ((u32*)state->shared_stream_data)[i] = UR(0XFFFFFFFF);

    state->shm_id_streampool = shm_id;
    
    state->total_exec = 0;
    state->total_priority = 0;

    state->entries = new vector<queue_entry*>();
    state->all_queued_streams = new map<u32,vector<input_stream*>*>();
    state->models = new map<u32,input_model*>();
    state->streamid_mmioaddr_mapping = new map<u32,u32>();
    state->simulators = new vector<Simulator*>();
    state->freed_streams = new map<u32,vector<input_stream*>*>();
    state->max_stream_used_len = new map<u32,s32>();

    state->num_fds = 0;
    state->shared_stream_used = 0;

    state->exit_none = 0;
    state->exit_outofseed = 0;
    state->exit_timeout = 0;
    state->exit_crash = 0;

    sprintf(shm_str,"%s/fuzzer_log.txt",log_dir);
    state->flog = fopen(shm_str,"w");
    if(!state->flog)
      fatal("create fuzzer log file error\n");

}



Simulator *allocate_new_simulator(FuzzState *state)
{
  static int start_fd = 100;
  static int cpu = 0;
  int i;
  pid_t pid;
  s32 tmp;
  int st_pipe[2], ctl_pipe[2];
  char shm_str[PATH_MAX];

  Simulator *simulator = new Simulator();
  simulator->state = state;
  simulator->map_size = state->map_size;

  s32 shm_id = shmget(IPC_PRIVATE, simulator->map_size, IPC_CREAT | IPC_EXCL | 0600);
  if (shm_id < 0) 
      fatal("shmget() failed");
  sprintf(shm_str,"%d",shm_id);
  setenv(SHM_ENV_VAR, shm_str, 1);
  simulator->trace_bits = (u8*)shmat(shm_id, NULL, 0);
  if (simulator->trace_bits == (void *)-1) 
      fatal("shmat() failed");
  memset(simulator->trace_bits,0,simulator->map_size);
  simulator->shm_id_trace_bit = shm_id;

  shm_id = shmget(IPC_PRIVATE, 0x1000, IPC_CREAT | IPC_EXCL | 0600);
  if (shm_id < 0) 
      fatal("shmget() failed");
  sprintf(shm_str,"%d",shm_id);
  setenv(SHM_SHARE_UNDISCOVER_STREAM_VAR, shm_str, 1);
  simulator->shared_undiscovered_stream_data = (u8*)shmat(shm_id, NULL, 0);
  if (simulator->shared_undiscovered_stream_data == (void *)-1) 
      fatal("shmat() failed");
  simulator->shm_id_undiscover_stream_var = shm_id;

  shm_id = shmget(IPC_PRIVATE, 0x1000, IPC_CREAT | IPC_EXCL | 0600);
  if (shm_id < 0) 
      fatal("shmget() failed");
  sprintf(shm_str,"%d",shm_id);
  setenv(SHM_SHARE_FUZZ_QUEUE_VAR, shm_str, 1);
  simulator->shared_fuzz_queue_data = (u8*)shmat(shm_id, NULL, 0);
  if (simulator->shared_fuzz_queue_data == (void *)-1) 
      fatal("shmat() failed");
  simulator->shm_id_fuzz_queue = shm_id;

  if (pipe(st_pipe) || pipe(ctl_pipe)) fatal("pipe() failed");
  if (dup2(ctl_pipe[0], start_fd) < 0) fatal("dup2() failed");
  if (dup2(st_pipe[1], start_fd + 1) < 0) fatal("dup2() failed");

  
  simulator->fd_ctl_to_simulator = ctl_pipe[1];
  simulator->fd_ctl_from_simulator = st_pipe[0];
  simulator->fuzz_stream = new map<u32,input_stream*>();

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

  start_fd += 2;
  cpu++;
  state->num_fds++;
  return simulator;
}


void copy_fuzz_data(Simulator *simulator)
{
  int i = 0;
  fuzz_queue *queue = (fuzz_queue *)simulator->shared_fuzz_queue_data;

  queue->num_streams = simulator->fuzz_entry->streams->size();

  for(auto it = simulator->fuzz_entry->streams->begin(); it != simulator->fuzz_entry->streams->end(); it++)
  {
    if(simulator->fuzz_stream->count(it->first))
    {
      queue->streams[i].offset_to_stream_area = (*simulator->fuzz_stream)[it->first]->offset_to_stream_area;
    }
    else
      queue->streams[i].offset_to_stream_area = it->second->offset_to_stream_area;
    i++;
  }

}
void sync_max_stream_used_len(Simulator *simulator)
{
  int i;
  u32 id;
  stream_metadata *metadata;
  FuzzState *state = simulator->state;
  fuzz_queue *queue = (fuzz_queue *)simulator->shared_fuzz_queue_data;

  for(i = 0 ; i < queue->num_streams ;i ++)
  {
    metadata = (stream_metadata *)(simulator->state->shared_stream_data + queue->streams[i].offset_to_stream_area);
    if(state->max_stream_used_len->count(metadata->stream_id) == 0)
      (*state->max_stream_used_len)[metadata->stream_id] = queue->streams[i].used;
    else if((*state->max_stream_used_len)[metadata->stream_id] < queue->streams[i].used)
      (*state->max_stream_used_len)[metadata->stream_id] = queue->streams[i].used; 
  }
}
bool sync_undiscovered_streams(FuzzState *state,queue_entry* q,Simulator *simulator)
{
  u32 id;
  undiscovered_streams *undiscover_streams = (undiscovered_streams *)simulator->shared_undiscovered_stream_data;

  for(int i = 0; i < undiscover_streams->num_streams ; i++)
  {
    id = undiscover_streams->streams[i];
    input_stream *stream = find_queued_stream(state,id);

    if(!stream)
      stream = allocate_new_stream(state,id, DEFAULT_STREAM_LEN);
    
    (*q->streams)[id] = stream;
  }

  return undiscover_streams->num_streams;
}

void show_stat()
{
  char output[PATH_MAX];

  u32 edges = count_non_255_bytes(global_state.virgin_bits, global_state.map_size);
  sprintf(output,"[%d] total exec %d edges:%d paths:%d used pool:%x none:%d timeout:%d outofseed:%d crash:%d\n",
  get_cur_time() / 1000,
  global_state.total_exec,
  edges,
  global_state.entries->size(),
  global_state.shared_stream_used,
  global_state.exit_none,
  global_state.exit_timeout,
  global_state.exit_outofseed,
  global_state.exit_crash
  );
  
  fprintf(stdout,output);
  fprintf(global_state.flog,output);
  
  
}
void save_coverage(FuzzState *state)
{
  FILE *f_coverage = fopen(coverage_file,"wb");
  fwrite(state->virgin_bits,state->map_size,1,f_coverage);
  fclose(f_coverage);
}


void sync_state(FuzzState *state)
{
  if(state->entries->size() == 0)
  {
    queue_entry *q = copy_queue(state,nullptr);
    #ifdef ENABLE_IRQ
    input_stream *stream = allocate_new_stream(state,IRQ_STREAM_ID,DEFAULT_STREAM_LEN);  //irq always there
    (*q->streams)[IRQ_STREAM_ID] = stream;
    #endif
    insert_queue(state,q);
  }
}

void run_modelling(FuzzState *state,Simulator *simulator)
{
  DIR* dir;
  char cmd[PATH_MAX];
  char tmp[PATH_MAX];
  struct dirent* dir_entry;
  dir = opendir(simulator->simulator_dump_dir);
  if (dir == NULL) {
      fatal("opendir error");
  }
  
  while ((dir_entry = readdir(dir)) != NULL) 
  {
    if (dir_entry->d_type == DT_REG  && strstr(dir_entry->d_name,MMIO_STATE_PREFIX)) 
    {
      u32 id = strtol(dir_entry->d_name + strlen(MMIO_STATE_PREFIX),0,16);
      if(state->models->find(id) == state->models->end())
      {
        printf("start model file:%s\n",dir_entry->d_name);
        sprintf(cmd,"%s/run_docker.sh %s fuzzware model ./dump/simulator_%d/%s -c ./model/simulator_%d/%s > /dev/null",
        FUZZWARE_PATH,
        out_dir,
        simulator->cpu,
        dir_entry->d_name,
        simulator->cpu,
        MMIO_MODEL_FILENAME);
        system(cmd);
        printf("model file done:%s\n",dir_entry->d_name);
      }
      sprintf(cmd,"mv %s/%s %s/",simulator->simulator_dump_dir,dir_entry->d_name,dump_backup_dir);
      system(cmd);
    }
  }
  closedir(dir);
}
void sync_models(FuzzState *state,Simulator *simulator)
{
  u32 mmio_id;
  int mode;
  char line[PATH_MAX];
  input_model *model = NULL;
  set<u32> *vals = NULL;
  sprintf(line,"%s/%s",simulator->simulator_model_dir,MMIO_MODEL_FILENAME);
  FILE *fp = fopen(line , "r");
  if(fp == NULL) 
  {
    return;
  }
  while(fgets(line, PATH_MAX, fp))
  {
    if(strstr(line,"unmodeled:"))
      mode = MODEL_NONE;
    if(strstr(line,"constant:"))
      mode = MODEL_CONSTANT;
    if(strstr(line,"set:"))
      mode = MODEL_VALUE_SET;
    if(strstr(line,"passthrough:"))
      mode = MODEL_PASSTHROUGH;
    if(strstr(line,"bitextract:"))
      mode = MODEL_BIT_EXTRACT;

    if(char *mmio_str = strstr(line,"_mmio_"))
    {
      u32 mmio_addr = strtol(mmio_str + strlen("_mmio_"), 0, 16);
      u32 mmio_pc = strtol(strstr(line,"pc_") + strlen("pc_"), 0, 16);
      mmio_id = hash_32_ext(mmio_addr) ^ hash_32_ext(mmio_pc);
      
      if(mode == MODEL_VALUE_SET)
      {
        vals = new set<u32>();
      }
      else
      {
        vals = nullptr;
      }
      model = new input_model();
      model->mode = mode;
      model->values = vals;
      (*state->models)[mmio_id] = model;
      (*state->streamid_mmioaddr_mapping)[mmio_id] = mmio_addr;
    }
    
    if(strstr(line,"access_size: "))
      model->access_size = strtol(strstr(line,"access_size: ") + strlen("access_size: "), 0, 16);
    if(strstr(line,"left_shift: "))
      model->left_shift = strtol(strstr(line,"left_shift: ") + strlen("left_shift: "),0,16);
    if(strstr(line,"mask: "))
      model->mask = strtol(strstr(line,"mask: ") + strlen("mask: "),0,16);
    if(strstr(line,"size: ") && !strstr(line,"access_size: "))
      model->size = strtol(strstr(line,"size: ") + strlen("size: "),0,16);
    if(strstr(line,"init_val: "))
      model->init_val = strtol(strstr(line,"init_val: ") + strlen("init_val: "),0,16);
    if(strstr(line,"val: ") && !strstr(line,"init_val: "))
      model->constant_val = strtol(strstr(line,"val: ") + strlen("val: "),0,16);
    if(strstr(line,"- "))
      vals->insert(strtol(strstr(line,"- ") + strlen("- "),0,16));
  }

  fclose(fp);
}

void fuzz_entry(Simulator *simulator)
{
  s32 tmp;
  memset(simulator->trace_bits,0,simulator->map_size);
  copy_fuzz_data(simulator);
  write(simulator->fd_ctl_to_simulator, &tmp,4);
  simulator->status = STATUS_RUNNING;
}
void fuzz_exit(Simulator *simulator,EXIT_INFO *exit_info)
{
  read(simulator->fd_ctl_from_simulator, exit_info,sizeof(EXIT_INFO));
  simulator->status = STATUS_FREE;
  simulator->state->total_exec++;
}
void find_all_streams_save_queue(FuzzState *state,queue_entry* entry,Simulator *simulator)
{
  EXIT_INFO exit_info;
  simulator->fuzz_entry = entry;
  bool found_new_streams = false;
  
  do
  {
    fuzz_entry(simulator);
    fuzz_exit(simulator,&exit_info);
    run_modelling(state,simulator);
    sync_models(state,simulator);
    found_new_streams = sync_undiscovered_streams(state,entry,simulator);
  }while(found_new_streams);

  classify_counts((u64*)simulator->trace_bits,simulator->map_size);
  has_new_bits_update_virgin(state->virgin_bits, simulator->trace_bits, simulator->map_size);
  entry->edges = count_bytes(simulator->trace_bits, simulator->map_size);
  entry->cksum = hash32(simulator->trace_bits,simulator->map_size);

  entry->priority = entry->edges + 1;
  if(exit_info.exit_code == EXIT_TIMEOUT)
    entry->priority = 1;
}

void fuzz_one_post(FuzzState *state,Simulator *simulator)
{
  queue_entry* fuzz_entry;
  map<u32,input_stream*> *fuzz_stream;
  EXIT_INFO exit_info;
  
  if(simulator->status == STATUS_FREE)
    return;
  fuzz_exit(simulator,&exit_info);
  fuzz_entry = simulator->fuzz_entry;
  fuzz_stream = simulator->fuzz_stream;

  
  classify_counts((u64*)simulator->trace_bits,simulator->map_size);
  int r = has_new_bits_update_virgin(state->virgin_bits, simulator->trace_bits, simulator->map_size);

  
  if(exit_info.exit_code == EXIT_CRASH)
  {
    state->exit_crash++;
    //save_crash(entry);
  }
  
  if(exit_info.exit_code == EXIT_NONE)
  {
    state->exit_none++;

  }
  if(exit_info.exit_code == EXIT_TIMEOUT)
  {
    state->exit_timeout++;
  }
  
  if(exit_info.exit_code == EXIT_OUTOFSEED)
  {
    state->exit_outofseed++; 
    
  }

  if(unlikely(r))
  {
    if(unlikely(r == 2))
      save_coverage(state);
    queue_entry* q = copy_queue(state,fuzz_entry);
    for(auto it = fuzz_stream->begin(); it != fuzz_stream->end(); ++it)
    {
      (*q->streams)[it->first] = it->second;
    }
    q->depth++;
    find_all_streams_save_queue(state,q,simulator);
    insert_queue(state,q);

  }
  else
  {
    for(auto it = fuzz_stream->begin(); it != fuzz_stream->end(); ++it)
    {
      free_stream(state,it->second);
    }
  }
  fuzz_stream->clear();
}

Simulator* get_avaliable_simulator(FuzzState *state)
{
  int ret,i;
  Simulator *simulator = nullptr;
  for(i = 0 ; i < state->simulators->size(); i++)
  {
    if((*state->simulators)[i]->status == STATUS_FREE)
    {
      return (*state->simulators)[i];
    }
      
  }
  ret = poll(state->fds, state->num_fds, -1);
  if (ret == -1) fatal("poll error");
  for (i = 0; i < state->num_fds; i++) 
  {
    if (state->fds[i].revents & POLLIN) 
    {
      return (*state->simulators)[i];
    }
  }
  fatal("no avaliable simulator\n");
  return nullptr;
}



inline void fuzz_queue(FuzzState *state,queue_entry* entry)
{
  s32 i;
  Simulator *simulator = NULL;
  input_stream *fuzz_stream;
  if(entry->streams->size() == 0)
  {
    simulator = get_avaliable_simulator(state); 
    find_all_streams_save_queue(state,entry,simulator);
  }
  for(auto it = entry->streams->begin() ; it != entry->streams->end() ; it++)
  {
    if(it->second->ptr->mode == MODEL_CONSTANT || it->second->ptr->mode == MODEL_PASSTHROUGH)
      continue;

    for(i = 0 ; i < it->second->priority ; i++)
    {
      simulator = get_avaliable_simulator(state);  
      fuzz_one_post(state,simulator);
      simulator->fuzz_entry = entry;
      if(UR(5))
      {
        fuzz_stream = havoc(state,it->second);
      }
      else
      {
        fuzz_stream = splicing(state,it->second);
        if(!fuzz_stream)
          continue;
      }
      (*simulator->fuzz_stream)[it->first] = fuzz_stream;
      fuzz_entry(simulator);
      
    } 
  }
  simulator = get_avaliable_simulator(state);  
  fuzz_one_post(state,simulator);
  simulator->fuzz_entry = entry;
  for(auto it = entry->streams->begin() ; it != entry->streams->end() ; it++)
  {
    if(it->second->ptr->mode == MODEL_CONSTANT || it->second->ptr->mode == MODEL_PASSTHROUGH)
      continue;
    if(UR(2))
    {
      if(UR(5))
        fuzz_stream = havoc(state,it->second);
      else
      {
        fuzz_stream = splicing(state,it->second);
        if(!fuzz_stream)
          continue;
      }
      (*simulator->fuzz_stream)[it->first] = fuzz_stream; 
    }
  }
  fuzz_entry(simulator);


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
        if((round & 0xf) == 0)
            show_stat();
    }
}



void fuzz(int cores)
{
  uint32_t tmp;
  Simulator *simulator;
  fuzzer_init(&global_state,FUZZ_COVERAGE_SIZE, SHARE_FUZZDATA_SIZE);
  for(int i = 0; i < cores; i++)
  {
    simulator = allocate_new_simulator(&global_state);
    global_state.simulators->push_back(simulator);

    printf("pid:%d wait for fork server\n",simulator->pid);
    read(simulator->fd_ctl_from_simulator, &tmp,4);
    printf("pid:%d fork server is up\n",simulator->pid);

    classify_counts((u64*)simulator->trace_bits,simulator->map_size);
    has_new_bits_update_virgin(global_state.virgin_bits, simulator->trace_bits, simulator->map_size);

    sync_models(&global_state,simulator);
  }
  fuzz_loop(&global_state);

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
void handle_ctrl_c(int signal) 
{
  int status;
  fclose(global_state.flog);
  for(Simulator * simulator : *global_state.simulators)
  {
    shmdt(simulator->trace_bits);
    shmdt(simulator->shared_fuzz_queue_data);
    shmdt(simulator->shared_undiscovered_stream_data);

    shmctl(simulator->shm_id_trace_bit, IPC_RMID, 0);
    shmctl(simulator->shm_id_undiscover_stream_var, IPC_RMID, 0);
    shmctl(simulator->shm_id_fuzz_queue, IPC_RMID, 0);

    printf("killing %d\n",simulator->pid);
    kill(simulator->pid,SIGKILL);
    waitpid(simulator->pid,&status,WEXITED | WSTOPPED);

  }
  shmdt(global_state.shared_stream_data);
  shmctl(global_state.shm_id_streampool, IPC_RMID, 0);

  if(signal == SIGSEGV)
    print_trace();
  exit(0);
}

void init_signal_handler()
{
  if (signal(SIGINT, handle_ctrl_c) == SIG_ERR) 
  {
    fatal("Error setting signal handler");
  }
  if (signal(SIGSEGV, handle_ctrl_c) == SIG_ERR) 
  {
    fatal("Error setting signal handler");
  }

  
}

int main(int argc, char **argv)
{
  int mode = -1;
  int opt;
  int cores;
  init_count_class16();
  init_signal_handler();
  while ((opt = getopt(argc, argv, "m:i:o:c:e:")) != -1) 
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
      default: /* '?' */
          printf("Usage error\n");
          exit(0);
      }
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
          "config:%s\n",
          queue_dir,
          crash_dir,
          log_dir,
          dump_dir,
          dump_backup_dir,
          simulator_bin,
          cores,
          mode,
          config);
  if(mode == MODE_FUZZ)
  {
    fuzz(cores);
  }
  if(mode == MODE_DEBUG)
  {

  }
  
}

