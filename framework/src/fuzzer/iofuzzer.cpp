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
#include "fuzzer.h"
#include "afl_utl.h"

using namespace std;





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

} global_state;


pthread_mutex_t *entry_mutex;

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


s32 fuzz_one(FuzzState *state,queue_entry* entry,u32* exit_info, u32* exit_pc);
void free_queue(queue_entry* q);
void fuzz_one_post(FuzzState *state,queue_entry* entry, input_stream *fuzzed_stream, s32 exit_code, u32 exit_info, u32 exit_pc);
void save_entry(queue_entry* entry, char *folder);
void sync_models(FuzzState *state,Simulator *simulator);
void havoc(FuzzState *state, input_stream* stream);
void find_all_streams_save_queue(FuzzState *state,queue_entry* entry);




inline u32 get_stream_used(FuzzState *state)
{
  return state->shared_stream_used;
}
inline void update_stream_ptr(FuzzState *state, u32 used)
{
  state->shared_stream_used += used;
}

input_stream *find_queued_stream(FuzzState *state,u32 id)
{
  for(input_stream *stream : *state->all_queued_streams)
  {
    if(stream->ptr->stream_id == id)
      return stream;
  }
  return nullptr;
}

void free_stream(FuzzState *state,input_stream *stream)
{
  u32 id = stream->ptr->stream_id;
  vector<input_stream *> *freed_streams;
  if(state->freed_streams->count(id) == 0)
  {
    (*state->freed_streams)[id] = new vector<input_stream *>();
  }
  freed_streams = (*state->freed_streams)[id];
  freed_streams->push_back(stream);

}
input_stream * allocate_freed_stream(FuzzState *state,u32 id)
{
  input_stream * ret;
  vector<input_stream *> *freed_streams;
  if(state->freed_streams->count(id) == 0)
    return nullptr;
  freed_streams = (*state->freed_streams)[id];
  if(freed_streams->size() == 0)
    return nullptr;
  ret = freed_streams->back();
  freed_streams->pop_back();
  return ret;
}
inline input_stream *allocate_new_stream(FuzzState *state,u32 id,input_stream *old , u32 len, u32 element_size)
{

  u8 *fuzz_data_ptr;

  input_stream *stream = new input_stream();
  if(!stream)
    fatal("allocate new_stream memory error\n");

  stream->offset_to_stream_area = get_stream_used(state);
  stream->ptr = (stream_metadata*)(state->shared_stream_data + stream->offset_to_stream_area);
  
  if(old)
  {
    stream->priority = old->priority;
    memcpy(stream->ptr,old->ptr,sizeof(stream_metadata));
    memcpy(stream->ptr->data,old->ptr->data,stream->ptr->len);
  }
  else
  {
    stream->ptr->stream_id = id;
    stream->ptr->len = len;
    stream->ptr->mode = MODEL_NONE;
    stream->ptr->element_size = element_size;
    stream->ptr->left_shift = 0;
    stream->priority = 1;
    for(int i = 0 ; i < (stream->ptr->len >> 2) ; i++)
      ((u32*)stream->ptr->data)[i] = UR(0XFFFFFFFF);
    {
      for(auto it = state->models->begin() ; it != state->models->end() ; it++)
      {
        if(it->first == stream->ptr->stream_id)
        {
          stream->ptr->mode = it->second->mode;
          if(stream->ptr->mode == MODEL_VALUE_SET)
          {
            stream->ptr->left_shift = 0;
            stream->ptr->element_size = 1;
            u32 *value_set_len_ptr = (u32 *)stream->ptr->data;
            u32 *value_set_ptr = (u32 *)(stream->ptr->data + sizeof(*value_set_len_ptr));
            *value_set_len_ptr = it->second->values->size();
            u32 i = 0;
            for(auto it2 = it->second->values->begin(); it2 != it->second->values->end(); it2++)
            {
              value_set_ptr[i++] = *it2;
            }
          }
          if(stream->ptr->mode == MODEL_CONSTANT)
          {
            stream->ptr->left_shift = 0;
            stream->ptr->element_size = 4;
            stream->ptr->len = 4;
            fuzz_data_ptr = stream->ptr->data;
            *(u32*)fuzz_data_ptr = it->second->constant_val;
          }
          if(stream->ptr->mode == MODEL_PASSTHROUGH)
          {
            stream->ptr->left_shift = 0;
            stream->ptr->element_size = 4;
            stream->ptr->len = 4;
          }
          if(stream->ptr->mode == MODEL_BIT_EXTRACT)
          {
            stream->ptr->left_shift = it->second->left_shift;
            stream->ptr->element_size = it->second->size;
          }

        }
      }
    }
  }
  update_stream_ptr(state, sizeof(stream_metadata) + stream->ptr->len);
  return stream;
}


inline void insert_queue(FuzzState *state,queue_entry* q)
{
  state->entries->push_back(q);
  state->total_priority += q->priority;
  for (auto it = q->streams->begin(); it != q->streams->end(); it++)
  {
    state->all_queued_streams->push_back(it->second);
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
    state->shm_id_streampool = shm_id;
    
    state->total_exec = 0;
    state->total_priority = 0;

    state->entries = new vector<queue_entry*>();
    state->all_queued_streams = new vector<input_stream*>();
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
    if(simulator->fuzz_stream && it->second->ptr->stream_id == simulator->fuzz_stream->ptr->stream_id)
      queue->streams[i].offset_to_stream_area = simulator->fuzz_stream->offset_to_stream_area;
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
      stream = allocate_new_stream(state,id,nullptr, DEFAULT_STREAM_LEN,DEFAULT_ELEMENT_SIZE);
    
    (*q->streams)[id] = stream;
  }

  return undiscover_streams->num_streams;
}

void show_stat(FuzzState *state)
{
  char output[PATH_MAX];

  u32 edges = count_non_255_bytes(state->virgin_bits, state->map_size);
  sprintf(output,"[%d] total exec %d edges:%d paths:%d used pool:%x none:%d timeout:%d outofseed:%d crash:%d\n",
  get_cur_time() / 1000,
  state->total_exec,
  edges,
  state->entries->size(),
  state->shared_stream_used,
  state->exit_none,
  state->exit_timeout,
  state->exit_outofseed,
  state->exit_crash
  );
  
  fprintf(stdout,output);
  fprintf(state->flog,output);
  
  
}
void save_coverage(FuzzState *state)
{
  FILE *f_coverage = fopen(coverage_file,"wb");
  fwrite(state->virgin_bits,state->map_size,1,f_coverage);
  fclose(f_coverage);
}


void sync_state(FuzzState *state)
{
  /*
  DIR* dir;
  struct dirent* dir_entry;

  
  load_stream_pool(state);

  sync_models(state);

  
  dir = opendir(queue_dir);
  if (dir == NULL)
      fatal("opendir error");

  while ((dir_entry = readdir(dir)) != NULL) 
  {
    if (dir_entry->d_type == DT_DIR && strcmp(dir_entry->d_name,".") && strcmp(dir_entry->d_name,"..")) 
    {
      u32 entry_id = strtol(dir_entry->d_name,0,16);
      if(state->cksums_entries->count(entry_id) == 0)
      {
        queue_entry *q = load_entry(state,entry_id,queue_dir);
        state->entries->push_back(q);
      }
    }
  }
  closedir(dir);
  
  */
  if(state->entries->size() == 0)
  {
    queue_entry *q = copy_queue(state,nullptr);
    #ifdef ENABLE_IRQ
    input_stream *stream = allocate_new_stream(state,IRQ_STREAM_ID,nullptr,nullptr,DEFAULT_STREAM_LEN,DEFAULT_IRQ_ELEMENT_SIZE);  //irq always there
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
    printf("model file %s not found, try without modelling or model already existed\n",line);
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
}
void find_all_streams_save_queue(FuzzState *state,queue_entry* entry,Simulator *simulator)
{
  EXIT_INFO exit_info;
  simulator->fuzz_entry = entry;
  simulator->fuzz_stream = nullptr;
  bool found_new_streams = false;
  
  do
  {
    fuzz_entry(simulator);
    fuzz_exit(simulator,&exit_info);
    sync_max_stream_used_len(simulator);
    run_modelling(state,simulator);
    sync_models(state,simulator);
    found_new_streams = sync_undiscovered_streams(state,entry,simulator);
  }while(found_new_streams);


  

  classify_counts((u64*)simulator->trace_bits,simulator->map_size);
  has_new_bits_update_virgin(state->virgin_bits, simulator->trace_bits, simulator->map_size);
  entry->edges = count_bytes(simulator->trace_bits, simulator->map_size);
  entry->cksum = hash32(simulator->trace_bits,simulator->map_size);

  entry->priority = entry->edges + 1;
}

void fuzz_one_post(FuzzState *state,Simulator *simulator)
{
  queue_entry* fuzz_entry;
  input_stream *fuzz_stream;
  EXIT_INFO exit_info;
  
  if(simulator->status == STATUS_FREE)
    return;
  fuzz_exit(simulator,&exit_info);
  sync_max_stream_used_len(simulator);
  fuzz_entry = simulator->fuzz_entry;
  fuzz_stream = simulator->fuzz_stream;

  
  classify_counts((u64*)simulator->trace_bits,simulator->map_size);
  int r = has_new_bits_update_virgin(state->virgin_bits, simulator->trace_bits, simulator->map_size);

  state->total_exec++;

  
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
    {
      save_coverage(state);
      fuzz_stream->priority += 5;
    }
    fuzz_stream->priority += 1;
    queue_entry* q = copy_queue(state,fuzz_entry);
    (*q->streams)[fuzz_stream->ptr->stream_id] = fuzz_stream;
    q->depth++;
    find_all_streams_save_queue(state,q,simulator);
    insert_queue(state,q);
    show_stat(state);
  }
  else
  {
    free_stream(state,fuzz_stream);
  }
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

void havoc(FuzzState *state,input_stream* stream)

{
  #define HAVOC_STACK 32
  #define HAVOC_TOKEN 20 
  #define ARITH_MAX   35
  s32 len;
  if(state->max_stream_used_len->count(stream->ptr->stream_id) == 0)
    len = stream->ptr->len;
  else
    len = (*state->max_stream_used_len)[stream->ptr->stream_id];
  u32 use_stacking = 1 + UR(8);
  // u32 use_stacking = 1 + UR(8);
  //s32 len = *stream->used_len == 0 ? *stream->len : *stream->used_len;
 
  u32 mode = stream->ptr->mode;
  u8 *data = stream->ptr->data;
  s32 i;
  
  if(len < 1)
    return;
  if(mode == MODEL_VALUE_SET)
  {
    u32 *value_set_len_ptr = (u32 *)stream->ptr->data;
    len -= sizeof(*value_set_len_ptr) + (*value_set_len_ptr) * sizeof(u32);
    data += sizeof(*value_set_len_ptr) + (*value_set_len_ptr) * sizeof(u32);
    for (i = 0; i < use_stacking; i++)
      data[UR(len)] = UR(*value_set_len_ptr);
    return;      
  }
  
  if(mode == MODEL_BIT_EXTRACT && stream->ptr->element_size == 1 && stream->ptr->left_shift == 0 && UR(5))
  {
    for (i = 0; i < use_stacking; i++) 
    {
      switch (UR(HAVOC_TOKEN))
      {
        case 0:
        {
          FLIP_BIT(data,UR(len << 3));
          break;
        }
        case 1:
        {
          ((s8*)data)[UR(len)] = interesting_8[UR(sizeof(interesting_8))];
          break;
        }
        case 2:
        {
          data[UR(len)] ^= 0xff;
          break;
        }
        case 3:
        {
          data[UR(len)] -= 1 + UR(ARITH_MAX);
          break;
        }
        case 4:
        {
          data[UR(len)] += 1 + UR(ARITH_MAX);
          break;
        }
        case 5:
          data[UR(len)] ^= UR(0x100);
          break;
        case 6:
        case 7:
        case 8:
        case 9:
        case 10:
        case 11:
        case 12:
        case 13:
        case 14:
        case 15:
        case 16:
        case 18:
        case 19:
        default:
        {
          data[UR(len)] = 0x61 + UR(0x7a - 0x60);  // ascii printable 
        }
      }
    }
    return;
  }
  
  for (i = 0; i < use_stacking; i++) 
  {
    {
      switch (UR(HAVOC_TOKEN))
      {
        case 0:
        {
          FLIP_BIT(data,UR(len << 3));
          break;
        }
        case 1:
        {
          ((s8*)data)[UR(len)] = interesting_8[UR(sizeof(interesting_8))];
          break;
        }
        case 2:
        {
          if(len < 2)
            break;
          s16* tmp = (s16*)(data + UR(len - 1));
          *tmp = interesting_16[UR(sizeof(interesting_16) >> 1)];
          break;
        }
        case 3:
        {
          if(len < 4)
            break;
          s32* tmp = (s32*)(data + UR(len - 3));
          *tmp = interesting_32[UR(sizeof(interesting_32) >> 2)];
          break;
        }
        case 4:
        {
          data[UR(len)] ^= 0xff;
          break;
        }
        case 5:
        {
          data[UR(len)] -= 1 + UR(ARITH_MAX);
          break;
        }
        case 6:
        {
          data[UR(len)] += 1 + UR(ARITH_MAX);
          break;
        }
        case 7:
        {
          if(len < 2)
            break;
          s16* tmp = (s16*)(data + UR(len - 1));
          *tmp -= 1 + UR(ARITH_MAX);
          break;
        }
        case 8:
        {
          if(len < 2)
            break;
          s16* tmp = (s16*)(data + UR(len - 1));
          *tmp += 1 + UR(ARITH_MAX);
          break;
        }
        case 9:
        {
          if(len < 4)
            break;
          s32* tmp = (s32*)(data + UR(len - 3));
          *tmp -= 1 + UR(ARITH_MAX);
          break;
        }
        case 10:
        {
          if(len < 4)
            break;
          s32* tmp = (s32*)(data + UR(len - 3));
          *tmp += 1 + UR(ARITH_MAX);
          break;
        }
        case 11:
        {
          ((s8*)data)[UR(len)] = UR(0x100);
          break;
        }
        case 12:
        {
          if(len < 2)
            break;
          s16* tmp = (s16*)(data + UR(len - 1));
          *tmp = UR(0x10000);
          break;
        }
        case 13:
        {
          if(len < 4)
            break;
          s32* tmp = (s32*)(data + UR(len - 3));
          *tmp = UR(0xffffffff);
          break;
        }
        case 14:
        {
          if(len < 8)
            break;
          s32* tmp1 = (s32*)(data + (UR(len - 7) & 0xfffffffc));
          s32* tmp2 = tmp1 + 1; //(s32*)(data + UR(len - 3));
          s32 val = UR(0xffffffff);
          *tmp1 = val;
          *tmp2 = val;
          break;
        }
          
        case 15:
        {
          if(len < 8)
            break;
          s32* tmp1 = (s32*)(data + (UR(len - 7) & 0xfffffffc));
          s32* tmp2 = tmp1 + 1; //(s32*)(data + UR(len - 3));
          s32 val = 0;
          *tmp1 = val;
          *tmp2 = val;
          break;
        }
        case 16:
        {
          if(len < 8)
            break;
          s32* tmp1 = (s32*)(data + (UR(len - 7) & 0xfffffffc));
          s32* tmp2 = tmp1 + 1; //(s32*)(data + UR(len - 3));
          s32 val = 0xffffffff;
          *tmp1 = val;
          *tmp2 = val;
          break;
        }
        case 17:
        case 18:
        case 19:
        {
          FLIP_BIT(data,UR(len << 3));
        }
        default:
        break;
      }
    }
    
  }
  
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
    show_stat(state);
  }

  for(auto it = entry->streams->begin() ; it != entry->streams->end() ; it++)
  {
    if(it->second->ptr->mode == MODEL_CONSTANT || it->second->ptr->mode == MODEL_PASSTHROUGH)
      continue;

    for(i = 0 ; i < it->second->priority ; i++)
    {
      simulator = get_avaliable_simulator(state);  // may block
      fuzz_one_post(state,simulator);

      fuzz_stream = allocate_freed_stream(state,it->second->ptr->stream_id);

      if(!fuzz_stream)
        fuzz_stream = allocate_new_stream(state,it->second->ptr->stream_id,it->second,0,0);
      havoc(state,fuzz_stream);
      
      simulator->fuzz_entry = entry;
      simulator->fuzz_stream = fuzz_stream;
      fuzz_entry(simulator);
    } 
  }
  show_stat(state);  
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
    while(1)
    {
        entry = select_entry(state);
        fuzz_queue(state,entry);
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
  exit(0);
}
void init_signal_handler()
{
  if (signal(SIGINT, handle_ctrl_c) == SIG_ERR) 
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

