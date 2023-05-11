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
#include "iofuzzer.h"
#include "afl_utl.h"

using namespace std;


void fatal(const char *msg)
{
    printf("%s",msg);
    fflush(stdout);
    system("reset");
    exit(0);
}



struct input_model
{
    int mode;
    #define MODEL_VALUE_SET 0
    #define MODEL_BIT_EXTRACT 1
    #define MODEL_CONSTANT 2
    #define MODEL_PASSTHROUGH 3
    #define MODEL_NONE 4
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
    u32 id;
    u8 *data;
    s32 len;
    s32 used;
    bool inited;

    //struct input_model *model;
};

struct queue_entry
{
    u32 edges; // bbls now
    u64 fuzz_times;
    s32 depth;
    map<u32,input_stream *> *streams;
    u32 favorate_stream;
    u32 exit_pc;

    u32 cksum;

    u64 exit_none;
    u64 exit_outofseed;
    u64 exit_timeout;
    u64 exit_crash;

    u32 num_mmio;
#define DEFAULT_PRIORITY 1
    s32 priority;

};
struct FuzzState
{
    u32 map_size;
    u8 *virgin_bits;
    u8 *trace_bits;
    u32 share_size;
    u8 *shared_stream_data;
    u8 *shared_irq_data;
    u8 *shared_undiscovered_stream_data;



    int fd_ctl_toserver;
    int fd_ctl_fromserver;
    int fd_data_toserver;
    int fd_data_fromserver;


    u32 total_exec;

    vector<queue_entry*> *entries;
    map<u32,queue_entry*> *cksums_entries;
    set<u32> *cksums;
    u8 *temp_compressed_bits;

    int cpu;
    int pid;
    int sync_times;

    set<u16> *irq_vals;
    map<u32,struct input_model*> *models;

    map<u32,u32> *streamid_mmioaddr_mapping;
};


pthread_mutex_t *entry_mutex;

char  in_dir[PATH_MAX];
char  out_dir[PATH_MAX];

char  queue_dir[PATH_MAX];
char  crash_dir[PATH_MAX];

char  log_dir[PATH_MAX];


char  state_dir[PATH_MAX];
char  state_backup_dir[PATH_MAX];
char  model_dir[PATH_MAX];
char  model_file[PATH_MAX];



s32 fuzz_one(FuzzState *state,queue_entry* entry,u32* exit_info, u32* exit_pc);
void free_queue(queue_entry* q);
bool fuzz_one_post(FuzzState *state,queue_entry* entry, s32 exit_code, u32 exit_info, u32 exit_pc);
void reset_queue(queue_entry* q);
void save_entry(queue_entry* entry, char *folder);
void sync_models(FuzzState *state);
void havoc(FuzzState *state, input_stream* stream);
void find_all_streams_save_queue(FuzzState *state,queue_entry* entry);


inline input_stream *new_stream(u32 id, char *file)
{
  input_stream *stream = new input_stream();
  if(!stream)
    fatal("allocate new_stream memory error\n");
  stream->id = id;
  stream->used = 0;
  stream->inited = false;
  if(file)
  {
    struct stat st;
    if (lstat(file, &st) || access(file, R_OK))
    {
      fatal("unable to access seed file\n");
    }
    FILE *fd = fopen(file,"rb");
    stream->len = st.st_size;
    stream->data = (u8*)malloc(stream->len);
    
    fread(stream->data,stream->len,1,fd);
    fclose(fd);
  }
  else
  {
    
    stream->data = (u8*)malloc(DEFAULT_STREAM_LEN);
    stream->len = DEFAULT_STREAM_LEN;
    for(int i = 0 ; i < (stream->len >> 2) ; i++)
      ((u32*)stream->data)[i] = UR(0XFFFFFFFF);
  }
  return stream;
}
inline queue_entry* copy_queue(queue_entry* q)
{
  queue_entry *entry = new queue_entry();
  entry->streams = new map<u32,input_stream *>();
  if(!entry || !entry->streams)
    fatal("allocate copy_queue memory error\n");
  if(q)
  {
    for (auto it = q->streams->begin(); it != q->streams->end(); it++)
    {
      input_stream *stream = new input_stream();
      stream->id = it->second->id;
      stream->len = it->second->len;
      stream->used = 0;
      stream->inited = false;
      stream->data = (u8*)malloc(stream->len);
      memcpy(stream->data,it->second->data,stream->len);
      entry->streams->insert({it->first , stream});
    }
    entry->depth = q->depth;
    entry->exit_pc = q->exit_pc;
  }
  else
  {
    entry->streams->insert({0xffffffff , new_stream(0xffffffff, 0)});  // irq is necessary for every entry
    entry->depth = 0;
  }
  
  entry->fuzz_times = 0;
  entry->favorate_stream = 0;
  entry->exit_none = 0;
  entry->exit_crash = 0;
  entry->exit_outofseed = 0;
  entry->exit_timeout = 0;
  entry->num_mmio = 0;
  
  return entry;
}



void fuzzer_init(FuzzState *state, u32 map_size, u32 share_size) 
{
    char shm_str[PATH_MAX];
    state->map_size = map_size;
    state->share_size = share_size;
    state->virgin_bits = (u8*)malloc(state->map_size);
    memset(state->virgin_bits, 0xff, state->map_size);

    s32 shm_id = shmget(IPC_PRIVATE, state->map_size, IPC_CREAT | IPC_EXCL | 0600);
    if (shm_id < 0) 
        fatal("shmget() failed");
    sprintf(shm_str,"%d",shm_id);
    setenv(SHM_ENV_VAR, shm_str, 1);
    state->trace_bits = (u8*)shmat(shm_id, NULL, 0);
    if (state->trace_bits == (void *)-1) 
        fatal("shmat() failed");

    shm_id = shmget(IPC_PRIVATE, state->share_size, IPC_CREAT | IPC_EXCL | 0600);
    if (shm_id < 0) 
        fatal("shmget() failed");
    sprintf(shm_str,"%d",shm_id);
    setenv(SHM_SHARE_STREAM_VAR, shm_str, 1);
    state->shared_stream_data = (u8*)shmat(shm_id, NULL, 0);
    if (state->shared_stream_data == (void *)-1) 
        fatal("shmat() failed");
    
    shm_id = shmget(IPC_PRIVATE, 0x5000, IPC_CREAT | IPC_EXCL | 0600);
    if (shm_id < 0) 
        fatal("shmget() failed");
    sprintf(shm_str,"%d",shm_id);
    setenv(SHM_SHARE_IRQ_VAR, shm_str, 1);
    state->shared_irq_data = (u8*)shmat(shm_id, NULL, 0);
    if (state->shared_irq_data == (void *)-1) 
        fatal("shmat() failed");

    shm_id = shmget(IPC_PRIVATE, 0x5000, IPC_CREAT | IPC_EXCL | 0600);
    if (shm_id < 0) 
        fatal("shmget() failed");
    sprintf(shm_str,"%d",shm_id);
    setenv(SHM_SHARE_UNDISCOVER_STREAM_VAR, shm_str, 1);
    state->shared_undiscovered_stream_data = (u8*)shmat(shm_id, NULL, 0);
    if (state->shared_undiscovered_stream_data == (void *)-1) 
        fatal("shmat() failed");
    
    int st_pipe[2], ctl_pipe[2], todata_pipe[2], fromdata_pipe[2];
    if (pipe(st_pipe) || pipe(ctl_pipe) || pipe(todata_pipe) || pipe(fromdata_pipe)) fatal("pipe() failed");
    if (dup2(ctl_pipe[0], FORKSRV_CTLFD) < 0) fatal("dup2() failed");
    if (dup2(st_pipe[1], FORKSRV_CTLFD + 1) < 0) fatal("dup2() failed");
    if (dup2(todata_pipe[0], FORKSRV_DATAFD) < 0) fatal("dup2() failed");
    if (dup2(fromdata_pipe[1], FORKSRV_DATAFD + 1) < 0) fatal("dup2() failed");
    state->fd_ctl_toserver = ctl_pipe[1];
    state->fd_ctl_fromserver = st_pipe[0];

    
    state->total_exec = 0;


    state->entries = new vector<struct queue_entry*>();
    state->cksums = new set<u32>();
    state->cksums_entries = new map<u32, struct queue_entry*>();
    state->temp_compressed_bits = (u8*)malloc(state->map_size >> 3);

    state->sync_times = 0;

    state->irq_vals = new set<u16>();
    state->models = new map<u32,struct input_model*>();

    state->streamid_mmioaddr_mapping = new map<u32,u32>();
}
inline void fork_server_up(FuzzState *state)
{
    printf("pid:%d wait for fork server\n",state->pid);
    s32 tmp;
    read(state->fd_ctl_fromserver, &tmp,4);
    printf("pid:%d fork server is up\n",state->pid);
}
inline void fork_server_runonce(FuzzState *state)
{
    s32 tmp;
    write(state->fd_ctl_toserver, &tmp,4);
}

s32 fork_server_getexit(FuzzState *state,u32 *exit_info, u32 *exit_pc, u32 *num_mmio)
{
    static s32 buf[128];
    read(state->fd_ctl_fromserver, buf,20);
    *exit_info = buf[1];
    *exit_pc = buf[2];
    *num_mmio = buf[3];
    return buf[0];
}


int run_controlled_process(char *cmd, bool need_dump_state)
{
	pid_t pid;
	char *child_arg[1000];

  child_arg[0] = cmd;
  if(need_dump_state)
    child_arg[1] = (char *)"y";
  else
    child_arg[1] = (char *)"n";

	child_arg[2] = state_dir;
  child_arg[3] = log_dir;
	child_arg[4] = NULL;
	pid = fork();
	if (pid < 0) fatal("fork error\n");
	else if(!pid)
	{
		execv(child_arg[0],child_arg);
	}
  return pid;
}

void copy_fuzz_data(FuzzState *state,queue_entry* entry)
{
  u32* num_streams_ptr = (u32*)state->shared_stream_data;
  *num_streams_ptr = entry->streams->size();
  u8 *ptr = state->shared_stream_data + 4;
  for (auto it = entry->streams->begin(); it != entry->streams->end(); it++)
  {
    
    *(uint32_t*)ptr = it->second->id;
    *(uint32_t*)(ptr+4) = it->second->len;
    *(uint32_t*)(ptr+8) = it->second->used;
    memcpy(ptr+12,it->second->data,it->second->len);
    ptr += 12 + it->second->len;
  }
  
}
bool sync_undiscovered_streams(FuzzState *state,queue_entry* q)
{
  bool found_new_stream = false;
  uint32_t* num_new_streams = (u32*)state->shared_undiscovered_stream_data;
  uint32_t* new_streams = num_new_streams + 1;

  for(int i = 0; i < *num_new_streams ; i++)
  {
    input_stream *stream = new_stream(new_streams[i],nullptr);
    q->streams->insert({new_streams[i] , stream});
    found_new_stream = true;

  }

  return found_new_stream;
}
void sync_irq_vals(FuzzState *state)
{
  u32* num_irq_vals = (u32 *)state->shared_irq_data;
  u16* irq_vals = (u16*)(num_irq_vals + 1);
  for(int i = 0; i < *num_irq_vals ; i++)
  {
    state->irq_vals->insert(irq_vals[i]);
  }
}
void show_stat(FuzzState *state)
{
  if(state->cpu != MAIN_CPU)
    return;
  u32 edges = count_non_255_bytes(state->virgin_bits, state->map_size);
  printf("[%d][%d] total exec %d sync:%d edges:%d paths:%d irqs:",state->cpu,get_cur_time() / 1000, state->total_exec,state->sync_times, edges,state->entries->size());
  for(auto it = state->irq_vals->begin(); it != state->irq_vals->end();it++)
  {
    printf("%d  ",*it);
  }
  printf("\n-----------queue details-----------\n");
  printf("id        depth     bbls      #streams  prio      favorate             none      seed      timeout   crash     exit_pc   num_mmio  exec_times\n");
  //int count = state->cksums_entries->size();
  for (auto it = state->cksums_entries->begin(); it != state->cksums_entries->end(); it++)
  {
    printf("%-10x%-10d%-10d%-10d%-10d%-10x:%-10x%-10d%-10d%-10d%-10d%-10x%-10d%-10d\n",
    it->second->cksum,
    it->second->depth,
    it->second->edges,
    it->second->streams->size(),
    it->second->priority,
    it->second->favorate_stream ? it->second->favorate_stream : 0,
    state->streamid_mmioaddr_mapping->find(it->second->favorate_stream) == state->streamid_mmioaddr_mapping->end() ? 0 : (*state->streamid_mmioaddr_mapping)[it->second->favorate_stream],
    it->second->exit_none ,
    it->second->exit_outofseed ,
    it->second->exit_timeout ,
    it->second->exit_crash ,
    it->second->exit_pc,
    it->second->num_mmio,
    it->second->fuzz_times);
  }
  
}
void save_crash(queue_entry* entry)
{
  save_entry(entry, crash_dir);
}
void save_entry(queue_entry* entry, char *folder)
{

  pthread_mutex_lock(entry_mutex);
  char entry_filename[PATH_MAX];
  char entry_folder[PATH_MAX];
  char entry_metafilename[PATH_MAX];

  DIR* dir;
  struct dirent* dir_entry;
  bool found_entry = false;

  dir = opendir(folder);
  if (dir == NULL) {
      fatal("opendir error");
  }

  while ((dir_entry = readdir(dir)) != NULL) 
  {
    if (dir_entry->d_type == DT_DIR && strcmp(dir_entry->d_name,".") && strcmp(dir_entry->d_name,"..")) 
    {
      u32 stream_id = strtol(dir_entry->d_name,0,16);
      if(stream_id == entry->cksum)
      {
        found_entry = true;
        break;
      }
    }
  }
  if(found_entry)
  {
    
    closedir(dir);
    pthread_mutex_unlock(entry_mutex);
    return;
  }

  sprintf(entry_folder,"%s/%08x",folder, entry->cksum);
  mkdir(entry_folder, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);


  sprintf(entry_metafilename,"%s/%s",entry_folder, "meta.data");
  
  FILE *f = fopen(entry_metafilename,"wb");

  if(!f)
    fatal("meta file open error\n");
  fclose(f);

  for (auto it = entry->streams->begin(); it != entry->streams->end(); it++)
  {
    sprintf(entry_filename,"%s/%08x",entry_folder,it->second->id);
    f = fopen(entry_filename,"wb");
    if(!f)
    {
      fatal("entry stream file open error\n");
    }
    fwrite(it->second->data,it->second->len,1,f);
    fclose(f);
  }
  closedir(dir);
  pthread_mutex_unlock(entry_mutex);

}
inline u32 get_num_undiscovered_stream(FuzzState *state)
{
  u32* num_new_streams = (u32*)state->shared_undiscovered_stream_data;
  return *num_new_streams;
}
queue_entry* load_entry(u32 id)
{
  char entry_filename[PATH_MAX];
  char entry_folder[PATH_MAX];
  char entry_metafilename[PATH_MAX];
  queue_entry *entry = copy_queue(nullptr);

  sprintf(entry_folder,"%s/%08x",queue_dir, id);
  sprintf(entry_metafilename,"%s/%s",entry_folder, "meta.data");


  FILE *f = fopen(entry_metafilename,"rb");
  if(f == NULL)
    fatal("metafile open error\n");
  fclose(f);

  DIR* dir;
  struct dirent* dir_entry;

  dir = opendir(entry_folder);
  if (dir == NULL) {
      fatal("opendir error");
  }
    
  while ((dir_entry = readdir(dir)) != NULL) 
  {
    if (dir_entry->d_type == DT_REG && !strstr(dir_entry->d_name,"meta.data")) 
    {
      u32 stream_id = strtol(dir_entry->d_name,0,16);
      sprintf(entry_filename,"%s/%08x",entry_folder,stream_id);
      input_stream *tmp = new_stream(stream_id,entry_filename);
      (*entry->streams)[stream_id] = tmp;  
    }
  }
  closedir(dir);
  return entry;
}


void sync_entries(FuzzState *state)
{
  vector<queue_entry *> out;
  DIR* dir;
  u32 exit_info,exit_pc;
  s32 exit_code;
  struct dirent* dir_entry;
  pthread_mutex_lock(entry_mutex);

  dir = opendir(queue_dir);
  if (dir == NULL)
      fatal("opendir error");

  while ((dir_entry = readdir(dir)) != NULL) 
  {
    if (dir_entry->d_type == DT_DIR && strcmp(dir_entry->d_name,".") && strcmp(dir_entry->d_name,"..")) 
    {
      u32 entry_id = strtol(dir_entry->d_name,0,16);
      if(state->cksums->find(entry_id) == state->cksums->end())
      {
        queue_entry *q = load_entry(entry_id);
        out.push_back(q);
      }
    }
  }
  closedir(dir);
  sync_models(state);
  pthread_mutex_unlock(entry_mutex);
  if(state->entries->size() == 0)
  {
    queue_entry *q = copy_queue(nullptr);
    out.push_back(q);
  }
  for(queue_entry * q : out)
  {
    find_all_streams_save_queue(state,q);
  }
  show_stat(state);
  
}

void run_modelling()
{
  DIR* dir;
  char cmd[PATH_MAX];
  char tmp[PATH_MAX];
  struct dirent* dir_entry;
  dir = opendir(state_dir);
  if (dir == NULL) {
      fatal("opendir error");
  }
  
  while ((dir_entry = readdir(dir)) != NULL) 
  {
    if (dir_entry->d_type == DT_REG && strcmp(dir_entry->d_name,".") && strcmp(dir_entry->d_name,"..")) 
    {
      printf("start model file:%s\n",dir_entry->d_name);
      sprintf(cmd,"%s/run_docker.sh %s fuzzware model ./state/%s -c ./model/model.yml > /dev/null","/home/w/hd/iofuzzer/fuzzware",out_dir,dir_entry->d_name);
      system(cmd);
      printf("model file done:%s\n",dir_entry->d_name);
      sprintf(cmd,"mv %s/%s %s/",state_dir,dir_entry->d_name,state_backup_dir);
      system(cmd);
      
    }
  }
  closedir(dir);
}
void sync_models(FuzzState *state)
{

  bool begin = false;
  u32 mmio_id;
  int mode;
  char line[PATH_MAX];
  struct input_model *model = NULL;
  set<u32> *vals = NULL;
  FILE *fp = fopen(model_file , "r");
  if(fp == NULL) 
  {
    printf("model file not found, try without modelling\n");
    return;
  }
  while(fgets(line, PATH_MAX, fp))
  {
    if(strstr(line,"unmodeled:"))
      begin = false;
    if(strstr(line,"mmio_models:"))
      begin = true;
    if(!begin)
      continue;

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
      mmio_id = hash_64(mmio_addr,32) ^ hash_64(mmio_pc,32);
      
      if(mode == MODEL_VALUE_SET)
      {
        vals = new set<u32>();
      }
      else
      {
        vals = nullptr;
      }
      model = (struct input_model*)malloc(sizeof(struct input_model));
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
inline void decrease_stream(input_stream *stream)
{
  s32 old_len = stream->len;
  s32 len = old_len >> 8;
  if(len < DEFAULT_STREAM_LEN)
    return;
  stream->data = (u8*)realloc(stream->data,len);
  stream->len = len;
  
}
inline void increase_stream(input_stream *stream)
{

  s32 old_len = stream->len;
  s32 len = old_len << 8;
  if(len > MAX_STREAM_LEN)
    return;
  stream->data = (u8*)realloc(stream->data,len);
  stream->len = len;

}

s32 fuzz_one(FuzzState *state,queue_entry* entry,u32* exit_info, u32* exit_pc)
{
  s32 exit_code;
  bool found_new_streams = false;
  memset(state->trace_bits,0,state->map_size);

  reset_queue(entry);

  copy_fuzz_data(state,entry);

  fork_server_runonce(state);

  exit_code = fork_server_getexit(state,exit_info,exit_pc,&entry->num_mmio);

  return exit_code;
  
}
void find_all_streams_save_queue(FuzzState *state,queue_entry* entry)
{
  u32 exit_info,exit_pc;
  s32 exit_code;
  bool found_new_streams = false;
  do
  {
    fuzz_one(state,entry,&exit_info,&exit_pc);
    
    found_new_streams = sync_undiscovered_streams(state,entry);
    
  }while(found_new_streams);

  run_modelling();
  sync_models(state);
  sync_irq_vals(state);
  classify_counts((u64*)state->trace_bits,state->map_size);
  has_new_bits_update_virgin(state->virgin_bits, state->trace_bits, state->map_size);
  entry->edges = count_bytes(state->trace_bits, state->map_size);
  // minimize_bits(state->temp_compressed_bits,state->trace_bits,state->map_size);
  // entry->cksum = hash32(state->temp_compressed_bits,state->map_size >> 2);
  entry->cksum = hash32(state->trace_bits,state->map_size);
  entry->exit_pc = exit_pc;
  state->entries->push_back(entry);
  state->cksums_entries->insert({entry->cksum , entry});
  state->cksums->insert(entry->cksum);
  save_entry(entry,queue_dir);

}
bool fuzz_one_post(FuzzState *state,queue_entry* entry, s32 exit_code, u32 exit_info, u32 exit_pc)
{
  bool found_new_entry = false;
  
  classify_counts((u64*)state->trace_bits,state->map_size);
  int r = has_new_bits_update_virgin(state->virgin_bits, state->trace_bits, state->map_size);
  state->total_exec++;
  entry->fuzz_times++;

  if(exit_code == EXIT_CRASH)
  {
    entry->exit_crash++;
    save_crash(entry);
  }
  
  if(exit_code == EXIT_NONE)
  {
    entry->exit_none++;

  }
  if(exit_code == EXIT_TIMEOUT)
  {
    entry->exit_timeout++;
  }
  
  if(exit_code == EXIT_OUTOFSEED)
  {
    entry->exit_outofseed++; 
    entry->favorate_stream = exit_info;
  }
  
  if(unlikely(r))
  {
    queue_entry* q = copy_queue(entry);
    q->depth++;
    find_all_streams_save_queue(state,q);
    show_stat(state);
    found_new_entry = true;
  
  }

  return found_new_entry;
}
void reset_queue(queue_entry* q)
{
  for (auto it = q->streams->begin(); it != q->streams->end(); it++)
  {
    it->second->used = 0;
  }
}

void free_queue(queue_entry* q)
{
  for (auto it = q->streams->begin(); it != q->streams->end(); it++)
  {
    if(it->second->data)
    {
      free(it->second->data);
    }
    delete it->second;
  }
  delete q->streams;
  delete q;
  
}

#define FLIP_BIT(_ar, _b) do { \
    u8* _arf = (u8*)(_ar); \
    u32 _bf = (_b); \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf) & 7)); \
  } while (0)
void havoc(FuzzState *state, input_stream* stream)
{
  #define HAVOC_STACK 32
  #define HAVOC_TOKEN 20
  #define ARITH_MAX   35
  u32 use_stacking = 1 + UR(stream->len >> 1);
  s32 len = stream->len;
  u8 *data = stream->data;
  s32 i;
  struct input_model *model;


  if(stream->id == 0xffffffff)   //for irq
  {
    if(state->irq_vals->size() == 0)
        return;
    for (i = 0; i < (len >> 1); i++)
    {
      auto it = state->irq_vals->begin();
      std::advance(it, UR(state->irq_vals->size()));
      u16* tmp = (u16*)(data + (UR(len - 1) & 0xfffffffe));
      *tmp = *it;
    }
    return;
  }
  if(state->models->find(stream->id) != state->models->end())
  {
    model = (*state->models)[stream->id];
    if(model->mode == MODEL_CONSTANT)
    {
      for (i = 0; i < (len >> 2); i++)
      {
        ((u32*)data)[i] = model->constant_val;
      }
      return;
    }
    else if (model->mode == MODEL_VALUE_SET)
    {
      for (i = 0; i < (len >> 2); i++)
      {
        auto it = model->values->begin();
        std::advance(it, UR(model->values->size()));
        ((u32*)data)[i] = *it;
        // u32* tmp = (u32*)(data + (UR(len - 3) & 0xfffffffc) );
        // *tmp = *it;
      }
      return;
    }
    // else if (model->mode == MODEL_BIT_EXTRACT)
    // {
    //   for (i = 0; i < use_stacking; i++)
    //   {
    //     u32 val = UR(1 << (model->size * 8) );
    //     u32* tmp = (u32*)(data + (UR(len - 3) & 0xfffffffc) );
    //     *tmp = val << model->left_shift;
    //   }
    //   return;
    // }
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
          s16* tmp = (s16*)(data + UR(len - 1));
          *tmp = interesting_16[UR(sizeof(interesting_16) >> 1)];
          break;
        }
        case 3:
        {
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
          s16* tmp = (s16*)(data + UR(len - 1));
          *tmp -= 1 + UR(ARITH_MAX);
          break;
        }
        case 8:
        {
          s16* tmp = (s16*)(data + UR(len - 1));
          *tmp += 1 + UR(ARITH_MAX);
          break;
        }
        case 9:
        {
          s32* tmp = (s32*)(data + UR(len - 3));
          *tmp -= 1 + UR(ARITH_MAX);
          break;
        }
        case 10:
        {
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
          s16* tmp = (s16*)(data + UR(len - 1));
          *tmp = UR(0x10000);
          break;
        }
        case 13:
        {
          s32* tmp = (s32*)(data + UR(len - 3));
          *tmp = UR(0xffffffff);
          break;
        }
        case 14:
        {
          s32* tmp1 = (s32*)(data + (UR(len - 7) & 0xfffffffc));
          s32* tmp2 = tmp1 + 1; //(s32*)(data + UR(len - 3));
          s32 val = UR(0xffffffff);
          *tmp1 = val;
          *tmp2 = val;
          break;
        }
          
        case 15:
        {
          s32* tmp1 = (s32*)(data + (UR(len - 7) & 0xfffffffc));
          s32* tmp2 = tmp1 + 1; //(s32*)(data + UR(len - 3));
          s32 val = 0;
          *tmp1 = val;
          *tmp2 = val;
          break;
        }
        case 16:
        {
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
void havoc_entry(FuzzState *state,queue_entry* q)
{
  for(auto it = q->streams->begin(); it != q->streams->end(); it++)
  {
    havoc(state,it->second);
  }
}
queue_entry* select_entry(FuzzState *state)
{
  assert(state->entries->size() != 0);
  s32 total_priority = 0;
  for(int i = 0; i < state->entries->size(); i++)
  {
    (*state->entries)[i]->priority = ((*state->entries)[i]->streams->size() + (*state->entries)[i]->edges) *  (*state->entries)[i]->depth;
    // (*state->entries)[i]->priority += (*state->entries)[i]->edges / 10;
    // if((*state->entries)[i]->exit_outofseed > (*state->entries)[i]->exit_timeout)
    //   (*state->entries)[i]->priority *= 1.2;
    total_priority += (*state->entries)[i]->priority;
  }
  if(total_priority == 0)
    return (*state->entries)[0];
  s32 random_number =  UR(total_priority);
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
  // not reachable
  return NULL;
}
void fuzz_loop(FuzzState *state, int cpu)
{ 
    u64 rounds = 0;
    u32 exit_info,exit_pc;
    s32 exit_code;
    s32 len;
    cpu_set_t  mask;
    state->cpu = cpu;
    CPU_ZERO(&mask);
    CPU_SET(cpu, &mask);
    sched_setaffinity(0, sizeof(mask), &mask);

    fork_server_up(state);

    sync_entries(state);

    u8 *org_buf = (u8 *)malloc(MAX_STREAM_LEN);
    vector<struct input_stream *> tmp_streams;
    while(1)
    {
      queue_entry* entry = select_entry(state);
      //for (int i = 0 ; i < 10 ; i++)
      
      {
        tmp_streams.clear();
        for (auto it = entry->streams->begin(); it != entry->streams->end(); it++)
        {
          if(it->second->id == entry->favorate_stream)
          {
            for(int j = 0 ; j < 10 ;j ++)
              tmp_streams.push_back(it->second);
          }
          else
            tmp_streams.push_back(it->second);
        }
        
        for(input_stream *stream : tmp_streams)
        {
          len = stream->len;  
          memcpy(org_buf, stream->data, len);
          havoc(state, stream);
          exit_code = fuzz_one(state,entry,&exit_info,&exit_pc);
          fuzz_one_post(state,entry,exit_code,exit_info,exit_pc);
          memcpy(stream->data, org_buf, len); 
        }  
        
      }
      if(entry->exit_outofseed >= 0x10000 
         && entry->streams->find(entry->favorate_stream) != (entry->streams->end()))
      {
        input_stream *stream = (*entry->streams)[entry->favorate_stream];
        len = stream->len;  
        memcpy(org_buf, stream->data, len);
        increase_stream(stream);
        havoc(state, stream);
        exit_code = fuzz_one(state,entry,&exit_info,&exit_pc);
        fuzz_one_post(state,entry,exit_code,exit_info,exit_pc);
        memcpy(stream->data, org_buf, len); 
        entry->exit_outofseed = 0;
      }
      {
        queue_entry* tmp = copy_queue(entry);
        havoc_entry(state,entry);
        exit_code = fuzz_one(state,entry,&exit_info,&exit_pc);
        fuzz_one_post(state,entry,exit_code,exit_info,exit_pc);
        free_queue(tmp);
      }
      
      rounds++;
      // if((rounds & 0xfff) == 0)
      //   sync_entries(state);
      if((rounds & 0xff) == 0)
        show_stat(state);
    }
    
}
void reproduce_queue(FuzzState *state, u32 id, char *queue_dir)
{
  fork_server_up(state);
  char entry_filename[PATH_MAX];
  char entry_folder[PATH_MAX];
  char entry_metafilename[PATH_MAX];
  u32 exit_info,exit_pc;
  s32 exit_code;
  sync_models(state);
  queue_entry* entry = copy_queue(nullptr);
  sprintf(entry_folder,"%s/%08x",queue_dir, id);

  DIR* dir;
  struct dirent* dir_entry;

  dir = opendir(entry_folder);
  if (dir == NULL) {
      fatal("opendir error");
  }
    
  while ((dir_entry = readdir(dir)) != NULL) 
  {
    if (dir_entry->d_type == DT_REG && !strstr(dir_entry->d_name,"meta.data")) 
    {
      u32 stream_id = strtol(dir_entry->d_name,0,16);
      sprintf(entry_filename,"%s/%08x",entry_folder,stream_id);
      input_stream *tmp = new_stream(stream_id,entry_filename);
      (*entry->streams)[stream_id] = tmp;  
    }
  }
  closedir(dir);
  exit_code = fuzz_one(state,entry,&exit_info,&exit_pc);
  printf("exit code :%d\n",exit_code);

}
void init_dir(int argc, char **argv)
{
  if(argc >= 4)
  {
    strcpy(in_dir,argv[1]);
    strcpy(out_dir,argv[2]);
  }
  else
  {
    printf("Usage: %s [%s] [%s] [%s] ...\n",argv[0], "in_dir", "out_dir","bin");
    exit(0);
  }
  sprintf(queue_dir,"%s",in_dir);
  sprintf(crash_dir,"%s/crash/",out_dir);
  sprintf(log_dir,"%s/log/",out_dir);
  sprintf(state_dir,"%s/state/",out_dir);
  sprintf(state_backup_dir,"%s/state_backup/",out_dir);
  sprintf(model_dir,"%s/model/",out_dir);
  sprintf(model_file,"%s/model.yml",model_dir);

  mkdir(in_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  mkdir(out_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  mkdir(queue_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  mkdir(crash_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  mkdir(log_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  mkdir(state_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  mkdir(state_backup_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  mkdir(model_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
}
void init_shared_mutex(void)
{
  int shmid;
  if ((shmid = shmget(ENTRY_MUTEX_KEY, ENTRY_MUTEX_MEM_SIZE, IPC_CREAT | 0666)) < 0) 
  {
    fatal("shmget error\n");
  }
  entry_mutex = (pthread_mutex_t *)shmat(shmid, NULL, 0);
  if (entry_mutex == (pthread_mutex_t *) -1) 
  {
    fatal("shmat error\n");
  }
  pthread_mutexattr_t attr;
  pthread_mutexattr_init(&attr);
  pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
  pthread_mutex_init(entry_mutex, &attr);
}


int fuzz(int argc, char **argv)
{
  int status;
  //long number_of_processors = sysconf(_SC_NPROCESSORS_ONLN);
  long number_of_processors = 1;
  for(int i = 0; i < number_of_processors; i++)
  {
    int pid = fork();
    if(pid == -1)
      fatal("fork error\n");
    else if(pid == 0)
    {
      FuzzState state;
      fuzzer_init(&state,1 << 16, 500 << 20);

      int pid = run_controlled_process(argv[3],i == MAIN_CPU);
      state.pid = pid;
      fuzz_loop(&state,i);
    }
  }
  wait(&status);
  return 1;

}
int test_crash(int argc, char **argv,char *id)
{
  
  FuzzState state;
  fuzzer_init(&state,1 << 16, 100 << 20);
  int pid = run_controlled_process(argv[3],false);
  state.pid = pid;
  reproduce_queue(&state, strtol(id,0,16),crash_dir);
  kill(pid,9);
  system("reset");
  return 1;
}
int debug_queue(int argc, char **argv,char *id)
{
  
  FuzzState state;
  fuzzer_init(&state,1 << 16, 100 << 20);
  int pid = run_controlled_process(argv[3],false);
  state.pid = pid;
  reproduce_queue(&state, strtol(id,0,16),queue_dir);
  kill(pid,9);
  system("reset");
  return 1;
}
int main(int argc, char **argv)
{
  
  init_dir(argc,argv);
  init_shared_mutex();
  init_count_class16();

  if(argc < 5)
  {
    printf("Usage: %s [%s] [%s] [%s] [fuzz/debug/crash] ...\n",argv[0], "in_dir", "out_dir","bin");
    exit(0);
  }
  if(!strcmp(argv[4], "fuzz"))
  {
    return fuzz(argc, argv);
  }
  if(!strcmp(argv[4], "debug"))
  {
    if(argc < 6)
    {
      printf("Usage: %s [%s] [%s] [%s] debug id\n",argv[0], "in_dir", "out_dir","bin");
      exit(0);
    }
    return debug_queue(argc,argv,argv[5]);
  }
  if(!strcmp(argv[4], "crash"))
  {
    if(argc < 6)
    {
      printf("Usage: %s [%s] [%s] [%s] crash id\n",argv[0], "in_dir", "out_dir","bin");
      exit(0);
    }
    return test_crash(argc,argv,argv[5]);
  }
}

