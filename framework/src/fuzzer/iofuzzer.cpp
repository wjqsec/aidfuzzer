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

int mode;



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
    u8 *ptr;
    u32 *stream_id;
    s32 *len;
    u32 *mode;
    s32 *element_size;
    s32 *left_shift;
    s32 *used_len;
    uint8_t *data;
};

struct queue_entry
{
    s32 depth;
    u32 edges;
    map<u32,input_stream *> *streams;
    set<u16> *irq_vals;
    u32 cksum;

#define DEFAULT_PRIORITY 1
    s32 priority;
};

struct Simulator
{
    u32 map_size;
    u8 *trace_bits;
    u8 *shared_fuzz_queue_data;
    u8 *shared_undiscovered_stream_data;

    

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
    input_stream* backup_stream;
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
    vector<input_stream*> *all_streams;
    map<u32,vector<input_stream*>*> *freed_streams;
    
    
    map<u32,input_model*> *models;

    map<u32,u32> *streamid_mmioaddr_mapping;

    FILE *flog;

    

    u64 exit_none;
    u64 exit_outofseed;
    u64 exit_timeout;
    u64 exit_crash;

    vector<Simulator *> *simulators;
#define MAX_NUM_PIPES 20
    int num_fds;
    struct pollfd fds[MAX_NUM_PIPES];
};


pthread_mutex_t *entry_mutex;

char  *in_dir;
char  *out_dir;

char *simulator_bin;

char  queue_dir[PATH_MAX];
char  crash_dir[PATH_MAX];

char  log_dir[PATH_MAX];


char  state_dir[PATH_MAX];
char  state_backup_dir[PATH_MAX];
char  model_dir[PATH_MAX];
char  model_file[PATH_MAX];
char  coverage_file[PATH_MAX];


s32 fuzz_one(FuzzState *state,queue_entry* entry,u32* exit_info, u32* exit_pc);
void free_queue(queue_entry* q);
void fuzz_one_post(FuzzState *state,queue_entry* entry, input_stream *fuzzed_stream, s32 exit_code, u32 exit_info, u32 exit_pc);
void save_entry(queue_entry* entry, char *folder);
void sync_models(FuzzState *state);
void havoc(FuzzState *state,queue_entry* q, input_stream* stream);
void find_all_streams_save_queue(FuzzState *state,queue_entry* entry);




inline u32 get_stream_used(FuzzState *state)
{
  return state->shared_stream_used;
}
inline void update_stream_ptr(FuzzState *state, u32 used)
{
  state->shared_stream_used += used;
}

input_stream *find_specific_stream(FuzzState *state,u32 id)
{
  for(input_stream *stream : *state->all_streams)
  {
    if(*stream->stream_id == id)
      return stream;
  }
  return nullptr;
}

void free_stream(FuzzState *state,input_stream *stream)
{
  vector<input_stream *> *freed_streams;
  if(state->freed_streams->count(*stream->stream_id) == 0)
  {
    (*state->freed_streams)[*stream->stream_id] = new vector<input_stream *>();
  }
  freed_streams = (*state->freed_streams)[*stream->stream_id];
  freed_streams->push_back(stream);

}
input_stream * allocate_old_stream(FuzzState *state,input_stream *stream)
{
  input_stream * ret;
  vector<input_stream *> *freed_streams;
  if(state->freed_streams->count(*stream->stream_id) == 0)
    return nullptr;
  freed_streams = (*state->freed_streams)[*stream->stream_id];
  if(freed_streams->size() == 0)
    return nullptr;
  ret = freed_streams->back();
  freed_streams->pop_back();
  ret->priority = stream->priority;
  memcpy(ret->data,stream->data,*stream->len);
  return ret;
}
inline input_stream *allocate_new_stream(FuzzState *state,u32 id,input_stream *old , u32 len, u32 element_size)
{
  u32 i;
  u32 fuzz_data_len;
  u8 *fuzz_data_ptr;

  input_stream *stream = new input_stream();
  if(!stream)
    fatal("allocate new_stream memory error\n");

  stream->offset_to_stream_area = get_stream_used(state);
  stream->ptr = state->shared_stream_data + stream->offset_to_stream_area;
  stream->stream_id = (u32 *)stream->ptr;

  stream->len = (s32*)(stream->ptr + sizeof(*stream->stream_id));
  stream->mode = (u32*)(stream->ptr + sizeof(*stream->stream_id) + sizeof(*stream->len));
  stream->element_size = (s32*)(stream->ptr + sizeof(*stream->stream_id) + sizeof(*stream->len) + sizeof(*stream->mode));
  stream->left_shift = (s32*)(stream->ptr + sizeof(*stream->stream_id) + sizeof(*stream->len) + sizeof(*stream->mode) + sizeof(*stream->element_size));
  stream->used_len = (s32*)(stream->ptr + sizeof(*stream->stream_id) + sizeof(*stream->len) + sizeof(*stream->mode) + sizeof(*stream->element_size) + sizeof(*stream->left_shift));
  stream->data = (u8*)(stream->ptr + sizeof(*stream->stream_id) + sizeof(*stream->len) + sizeof(*stream->mode) + sizeof(*stream->element_size) + sizeof(*stream->left_shift) + sizeof(*stream->used_len));
  
  if(old)
  {
    //stream->model = old->model;
    *stream->stream_id = *old->stream_id;
    *stream->mode = *old->mode;
    *stream->element_size = *old->element_size;
    *stream->len = *old->len;
    *stream->left_shift = *old->left_shift;
    *stream->used_len = *old->used_len;
    stream->priority = old->priority;
    memcpy(stream->data,old->data,*stream->len);
  }
  else
  {
    *stream->left_shift = 0;
    *stream->mode = MODEL_NONE;
    *stream->stream_id = id;
    *stream->len = len;
    *stream->element_size = element_size;
    *stream->used_len = 0;
    stream->priority = 1;
    for(int i = 0 ; i < (*stream->len >> 2) ; i++)
      ((u32*)stream->data)[i] = UR(0XFFFFFFFF);
    {
      for(auto it = state->models->begin() ; it != state->models->end() ; it++)
      {
        if(it->first == *stream->stream_id)
        {
         
          *stream->mode = it->second->mode;
          if(*stream->mode == MODEL_VALUE_SET)
          {
            *stream->left_shift = 0;
            *stream->element_size = 1;
            u32 *value_set_len_ptr = (u32 *)stream->data;
            u32 *value_set_ptr = (u32 *)(stream->data + sizeof(*value_set_len_ptr));
            *value_set_len_ptr = it->second->values->size();
            i = 0;
            for(auto it2 = it->second->values->begin(); it2 != it->second->values->end(); it2++)
            {
              value_set_ptr[i++] = *it2;
            }
            fuzz_data_ptr = stream->data + sizeof(*value_set_len_ptr) + i * sizeof(*value_set_ptr);
            fuzz_data_len = *stream->len - sizeof(*value_set_len_ptr) - i * sizeof(*value_set_ptr);
            for(i = 0 ; i < fuzz_data_len ; i++)
            {
              fuzz_data_ptr[i] = UR(*value_set_len_ptr);
            }
          }
          if(*stream->mode == MODEL_CONSTANT)
          {
            *stream->left_shift = 0;
            *stream->element_size = 4;
            *stream->len = 4;
            fuzz_data_ptr = stream->data;
            *(u32*)fuzz_data_ptr = it->second->constant_val;
          }
          if(*stream->mode == MODEL_PASSTHROUGH)
          {
            *stream->left_shift = 0;
            *stream->element_size = 1;
            *stream->len = 4;
          }
          if(*stream->mode == MODEL_BIT_EXTRACT)
          {
            *stream->left_shift = it->second->left_shift;
            *stream->element_size = it->second->size;
            fuzz_data_ptr = stream->data;
            fuzz_data_len = *stream->len;
            for(i = 0 ; i < fuzz_data_len ; i++)
            {
              fuzz_data_ptr[i] = UR(0xff);
            }
          }

        }
      }
    }
    
  }
  state->all_streams->push_back(stream);
  update_stream_ptr(state, sizeof(*stream->stream_id) + sizeof(*stream->len) + sizeof(*stream->mode) + sizeof(*stream->element_size) + sizeof(*stream->left_shift) + sizeof(*stream->used_len) + *stream->len);
  return stream;
}


inline void insert_queue(FuzzState *state,queue_entry* q)
{
  state->entries->push_back(q);
  state->total_priority += q->priority;
}
inline queue_entry* copy_queue(FuzzState *state,queue_entry* q)
{
  queue_entry *entry = new queue_entry();
  entry->depth = 1;
  entry->priority = DEFAULT_PRIORITY;
  entry->streams = new map<u32,input_stream*>();
  entry->irq_vals = new set<u16>();
  if(q)
  {
    entry->streams->insert(q->streams->begin(), q->streams->end());
    entry->irq_vals->insert(q->irq_vals->begin(), q->irq_vals->end());
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

    
    state->total_exec = 0;
    state->total_priority = 0;

    state->entries = new vector<struct queue_entry*>();
    state->all_streams = new vector<input_stream*>();
    state->models = new map<u32,struct input_model*>();
    state->streamid_mmioaddr_mapping = new map<u32,u32>();
    state->simulators = new vector<Simulator*>();
    state->freed_streams = new map<u32,vector<input_stream*>*>();

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
  simulator->map_size = state->map_size;

  s32 shm_id = shmget(IPC_PRIVATE, simulator->map_size, IPC_CREAT | IPC_EXCL | 0600);
  if (shm_id < 0) 
      fatal("shmget() failed");
  sprintf(shm_str,"%d",shm_id);
  setenv(SHM_ENV_VAR, shm_str, 1);
  simulator->trace_bits = (u8*)shmat(shm_id, NULL, 0);
  if (simulator->trace_bits == (void *)-1) 
      fatal("shmat() failed");

  shm_id = shmget(IPC_PRIVATE, 0x1000, IPC_CREAT | IPC_EXCL | 0600);
  if (shm_id < 0) 
      fatal("shmget() failed");
  sprintf(shm_str,"%d",shm_id);
  setenv(SHM_SHARE_UNDISCOVER_STREAM_VAR, shm_str, 1);
  simulator->shared_undiscovered_stream_data = (u8*)shmat(shm_id, NULL, 0);
  if (simulator->shared_undiscovered_stream_data == (void *)-1) 
      fatal("shmat() failed");

  shm_id = shmget(IPC_PRIVATE, 0x1000, IPC_CREAT | IPC_EXCL | 0600);
  if (shm_id < 0) 
      fatal("shmget() failed");
  sprintf(shm_str,"%d",shm_id);
  setenv(SHM_SHARE_FUZZ_QUEUE_VAR, shm_str, 1);
  simulator->shared_fuzz_queue_data = (u8*)shmat(shm_id, NULL, 0);
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

  simulator->simulator_dump_dir = alloc_printf("%s/simulator_%d",state_dir,cpu);
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
  child_arg[i++] = NULL;


  pid = fork();
	if (pid < 0) fatal("fork error\n");
	else if(!pid)
	{
		execv(child_arg[0],child_arg);
	}
  
  printf("pid:%d wait for fork server\n",pid);
  read(simulator->fd_ctl_from_simulator, &tmp,4);
  printf("pid:%d fork server is up\n",pid);

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
  u32 *queue_ptr = (u32 *)simulator->shared_fuzz_queue_data;

  for(auto it = simulator->fuzz_entry->streams->begin(); it != simulator->fuzz_entry->streams->end(); it++)
  {
    if(simulator->fuzz_stream && *it->second->stream_id == *simulator->fuzz_stream->stream_id)
      queue_ptr[i++] = simulator->fuzz_stream->offset_to_stream_area;
    else
      queue_ptr[i++] = it->second->offset_to_stream_area;
  }

  queue_ptr[i] = 0xffffffff;
}
bool sync_undiscovered_streams(FuzzState *state,queue_entry* q,Simulator *simulator)
{
  uint32_t* num_new_streams = (u32*)simulator->shared_undiscovered_stream_data;
  uint32_t* new_streams = num_new_streams + 1;

  for(int i = 0; i < *num_new_streams ; i++)
  {
    input_stream *stream = find_specific_stream(state,new_streams[i]);

    if(!stream)
      stream = allocate_new_stream(state,new_streams[i],nullptr, DEFAULT_STREAM_LEN,DEFAULT_ELEMENT_SIZE);
    
    (*q->streams)[new_streams[i]] = stream;
  }

  return *num_new_streams;
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
  
  // printf("\n-----------queue details-----------\n");
  // fprintf(stdout,"id        depth     bbls      #streams  prio      favorate             none      seed      timeout   crash     exit_pc   num_mmio  exec_times\n");
  // fprintf(state->flog,"id        depth     bbls      #streams  prio      favorate             none      seed      timeout   crash     exit_pc   num_mmio  exec_times\n");
  
  // int count = state->cksums_entries->size();
  // for (auto it = state->cksums_entries->begin(); it != state->cksums_entries->end(); it++)
  // {
  //   printf("%-10x%-10d%-10d%-10d%-10d%-10x:%-10x%-10d%-10d%-10d%-10d%-10x%-10d%-10d\n",
  //   it->second->cksum,
  //   it->second->depth,
  //   it->second->edges,
  //   it->second->streams->size(),
  //   it->second->priority,
  //   it->second->favorate_stream ? it->second->favorate_stream : 0,
  //   state->streamid_mmioaddr_mapping->find(it->second->favorate_stream) == state->streamid_mmioaddr_mapping->end() ? 0 : (*state->streamid_mmioaddr_mapping)[it->second->favorate_stream],
  //   it->second->exit_none ,
  //   it->second->exit_outofseed ,
  //   it->second->exit_timeout ,
  //   it->second->exit_crash ,
  //   it->second->exit_pc,
  //   it->second->num_mmio,
  //   it->second->fuzz_times);
  // }

  // for(queue_entry *q : *state->entries)
  // {
  //   fprintf(stdout,"%-10x%-10d%-10d%-10d%-10d%-10x:%-10x%-10d%-10d%-10d%-10d%-10x%-10d%-10d\n",
  //   q->cksum,
  //   q->depth,
  //   q->edges,
  //   q->streams->size(),
  //   q->priority,
  //   q->favorate_stream ? q->favorate_stream : 0,
  //   state->streamid_mmioaddr_mapping->find(q->favorate_stream) == state->streamid_mmioaddr_mapping->end() ? 0 : (*state->streamid_mmioaddr_mapping)[q->favorate_stream],
  //   q->exit_none ,
  //   q->exit_outofseed ,
  //   q->exit_timeout ,
  //   q->exit_crash ,
  //   q->exit_pc,
  //   q->num_mmio,
  //   q->fuzz_times);

  //   fprintf(state->flog,"%-10x%-10d%-10d%-10d%-10d%-10x:%-10x%-10d%-10d%-10d%-10d%-10x%-10d%-10d\n",
  //   q->cksum,
  //   q->depth,
  //   q->edges,
  //   q->streams->size(),
  //   q->priority,
  //   q->favorate_stream ? q->favorate_stream : 0,
  //   state->streamid_mmioaddr_mapping->find(q->favorate_stream) == state->streamid_mmioaddr_mapping->end() ? 0 : (*state->streamid_mmioaddr_mapping)[q->favorate_stream],
  //   q->exit_none ,
  //   q->exit_outofseed ,
  //   q->exit_timeout ,
  //   q->exit_crash ,
  //   q->exit_pc,
  //   q->num_mmio,
  //   q->fuzz_times);
  // }
  
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
    state->entries->push_back(q);
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
        sprintf(cmd,"%s/run_docker.sh %s fuzzware model ./%s -c ./%s > /dev/null",FUZZWARE_PATH,simulator->simulator_dump_dir,dir_entry->d_name,MMIO_MODEL_FILENAME);
        system(cmd);
        printf("model file done:%s\n",dir_entry->d_name);
      }
      sprintf(cmd,"mv %s/%s %s/",simulator->simulator_dump_dir,dir_entry->d_name,state_backup_dir);
      system(cmd);
    }
  }
  closedir(dir);
}
void sync_models(FuzzState *state,Simulator *simulator)
{

  bool begin = false;
  u32 mmio_id;
  int mode;
  char line[PATH_MAX];
  struct input_model *model = NULL;
  set<u32> *vals = NULL;
  sprintf(line,"%s/%s",simulator->simulator_dump_dir,MMIO_MODEL_FILENAME);
  FILE *fp = fopen(line , "r");
  if(fp == NULL) 
  {
    printf("model file not found, try without modelling\n");
    return;
  }
  while(fgets(line, PATH_MAX, fp))
  {
    if(strstr(line,"unmodeled:"))
      mode = MODEL_NONE;
    // if(strstr(line,"mmio_models:"))
    //   begin = true;

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
      mmio_id = hash_32(mmio_addr) ^ hash_32(mmio_pc);
      
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

void fuzz_one(Simulator *simulator)
{
  s32 tmp;
  memset(simulator->trace_bits,0,simulator->map_size);
  copy_fuzz_data(simulator);
  write(simulator->fd_ctl_to_simulator, &tmp,4);
  simulator->status = STATUS_RUNNING;
}
void find_all_streams_save_queue(FuzzState *state,queue_entry* entry,Simulator *simulator)
{
  static u32 buf[EXIT_INFORMATION_SIZE];
  simulator->fuzz_entry = entry;
  simulator->fuzz_stream = nullptr;
  simulator->backup_stream = nullptr;
  bool found_new_streams = false;
  do
  {
    fuzz_one(simulator);
    read(simulator->fd_ctl_from_simulator, buf,EXIT_INFORMATION_SIZE);
    run_modelling(state,simulator);
    sync_models(state,simulator);
    #ifdef ENABLE_IRQ
    sync_irq_vals(state,entry);
    #endif
    found_new_streams = sync_undiscovered_streams(state,entry,simulator);
    
  }while(found_new_streams);

  classify_counts((u64*)simulator->trace_bits,simulator->map_size);
  has_new_bits_update_virgin(state->virgin_bits, simulator->trace_bits, simulator->map_size);
  entry->edges = count_bytes(simulator->trace_bits, simulator->map_size);
  entry->cksum = hash32(simulator->trace_bits,simulator->map_size);

  // entry->priority = ((entry->edges * entry->depth) / 10) + 1;
  //entry->priority = (int)(entry->edges / 10) + 1;
  entry->priority = entry->edges * entry->depth + 1;
  
  insert_queue(state,entry);
  //save_stream_pool(state);

  //save_entry(entry,queue_dir);

  simulator->status = STATUS_FREE;
}
void fuzz_one_post(FuzzState *state,Simulator *simulator)
{
  queue_entry* fuzz_entry;
  input_stream *fuzz_stream;
  input_stream *backup_stream;
  static u32 buf[EXIT_INFORMATION_SIZE];
  u32 exit_code,exit_info,exit_pc,num_mmio;
  
  if(simulator->status == STATUS_FREE)
    return;

  
  fuzz_entry = simulator->fuzz_entry;
  fuzz_stream = simulator->fuzz_stream;
  backup_stream = simulator->backup_stream;

  read(simulator->fd_ctl_from_simulator, buf,EXIT_INFORMATION_SIZE);
  exit_code = buf[0];
  exit_info = buf[1];
  exit_pc = buf[2];

  
  classify_counts((u64*)simulator->trace_bits,simulator->map_size);
  int r = has_new_bits_update_virgin(state->virgin_bits, simulator->trace_bits, simulator->map_size);

  state->total_exec++;

  
  
  if(exit_code == EXIT_CRASH)
  {
    state->exit_crash++;
    //save_crash(entry);
  }
  
  if(exit_code == EXIT_NONE)
  {
    state->exit_none++;

  }
  if(exit_code == EXIT_TIMEOUT)
  {
    state->exit_timeout++;
  }
  
  if(exit_code == EXIT_OUTOFSEED)
  {
    state->exit_outofseed++; 
    
  }
  
  if(unlikely(r))
  {
    if(unlikely(r == 2))
    {
      save_coverage(state);
      if(*fuzz_stream->mode == MODEL_BIT_EXTRACT || *fuzz_stream->mode == MODEL_NONE)
        fuzz_stream->priority += 5;
    }
    queue_entry* q = copy_queue(state,fuzz_entry);
    q->depth++;
    find_all_streams_save_queue(state,q,simulator);
   
    show_stat(state);
  }
  else
  {
    free_stream(state,fuzz_stream);
  }
  simulator->status = STATUS_FREE;


}

Simulator* get_avaliable_simulator(FuzzState *state)
{
  int ret,i;
  Simulator *simulator = nullptr;
  for(i = 0 ; i < state->simulators->size(); i++)
  {
    if((*state->simulators)[i]->status == STATUS_FREE)
      simulator = (*state->simulators)[i];
  }
  if(simulator)
    return simulator;
  ret = poll(state->fds, state->num_fds, -1);
  if (ret == -1) fatal("poll error");
  for (i = 0; i < state->num_fds; i++) 
  {
    if (state->fds[i].revents & POLLIN) 
    {
      simulator = (*state->simulators)[i];
    }
  }
  if(!simulator)
    fatal("no avaliable simulator\n");
  return simulator;
}

void havoc(input_stream* stream)
{
  #define HAVOC_STACK 32
  #define HAVOC_TOKEN 20 
  #define ARITH_MAX   35
  // u32 use_stacking = 1 + UR(*stream->len >> 2);
  // u32 use_stacking = 1 + UR(8);
  s32 len = *stream->used_len == 0 ? *stream->len : *stream->used_len;
  u32 use_stacking = 1 + UR((len >> 2) + 1);
  u8 *data = stream->data;
  s32 i;

  if(len < 1)
    return;
  if(*stream->mode == MODEL_VALUE_SET)
  {
    u32 *value_set_len_ptr = (u32 *)stream->data;
    len -= sizeof(*value_set_len_ptr) + (*value_set_len_ptr) * sizeof(u32);
    data += sizeof(*value_set_len_ptr) + (*value_set_len_ptr) * sizeof(u32);
    for (i = 0; i < use_stacking; i++)
      data[UR(len)] = UR(*value_set_len_ptr);
    return;      
  }
  
  if(*stream->mode == MODEL_BIT_EXTRACT && *stream->element_size == 1 && *stream->left_shift == 0 && UR(5))
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
        {
          data[UR(len)] = 0x20 + UR(0x7e - 0x20);  // ascii printable 
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
    if(*it->second->mode == MODEL_CONSTANT || *it->second->mode == MODEL_PASSTHROUGH)
      continue;

    for(i = 0 ; i < it->second->priority ; i++)
    {
      simulator = get_avaliable_simulator(state);  // may block
      fuzz_one_post(state,simulator);

      fuzz_stream = allocate_old_stream(state,it->second);

      if(!fuzz_stream)
        fuzz_stream = allocate_new_stream(state,*it->second->stream_id,it->second,0,0);
      
      havoc(fuzz_stream);
      
      simulator->fuzz_entry = entry;
      simulator->fuzz_stream = fuzz_stream;
      simulator->backup_stream = it->second;
      fuzz_one(simulator);
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



void fuzz()
{
  long number_of_processors = 1;
  //number_of_processors = sysconf(_SC_NPROCESSORS_ONLN);
  
  FuzzState state;
  Simulator *simulator;
  fuzzer_init(&state,FUZZ_COVERAGE_SIZE, SHARE_FUZZDATA_SIZE);
  for(int i = 0; i < number_of_processors; i++)
  {
    simulator = allocate_new_simulator(&state);
    state.simulators->push_back(simulator);
  }
  exit(0);
  fuzz_loop(&state);

}


void init_dir(void)
{

  sprintf(queue_dir,"%s",in_dir);
  sprintf(crash_dir,"%s/crash/",out_dir);
  sprintf(log_dir,"%s/log/",out_dir);
  sprintf(state_dir,"%s/state/",out_dir);
  sprintf(state_backup_dir,"%s/state_backup/",out_dir);
  sprintf(coverage_file,"%s/coverage.bin",out_dir);

  mkdir(in_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  mkdir(out_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  mkdir(queue_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  mkdir(crash_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  mkdir(log_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  mkdir(state_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  mkdir(state_backup_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
}

int main(int argc, char **argv)
{
  int opt;
  init_count_class16();

  while ((opt = getopt(argc, argv, "m:i:o:")) != -1) 
  {
      switch (opt) {
      case 'm':
          if(strcmp(optarg, "fuzz") == 0)
          {
            mode = MODE_FUZZ;
          }
          if(strcmp(optarg, "debug") == 0)
          {
            mode = MODE_DEBUG;
          }
          break;
      case 'i':
          in_dir = optarg;
          break;
      case 'o':
          out_dir = optarg;
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
          "state_dir:%s\n"
          "state_backup_dir:%s\n"
          "simulator_bin:%s\n",
          queue_dir,
          crash_dir,
          log_dir,
          state_dir,
          state_backup_dir,
          simulator_bin);
  if(mode == MODE_FUZZ)
  {
    fuzz();
  }
  if(mode == MODE_DEBUG)
  {

  }
  
}

