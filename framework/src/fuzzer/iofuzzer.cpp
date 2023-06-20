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


inline static u64 get_cur_time(void) {

  struct timeval tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);

}

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
    u32 priority;
    u32 offset_to_stream_area;
    u8 *ptr;
    u32 *stream_id;
    s32 *len;
    u32 *mode;
    s32 *element_size;
    s32 *left_shift;
    s32 *used_len;
    uint8_t *data;
    //input_model *model;
};

struct queue_entry
{
    u32 edges; // bbls now
    u64 fuzz_times;
    s32 depth;
    map<u32,input_stream *> *streams;
    set<u16> *irq_vals;
    u32 cksum;

    u64 exit_none;
    u64 exit_outofseed;
    u64 exit_timeout;
    u64 exit_crash;

    u32 exit_pc;

    u32 favorate_stream;
    
    u32 num_mmio;
#define DEFAULT_PRIORITY 1
    s32 priority;

    bool increased;

};
struct FuzzState
{
    u32 map_size;
    u8 *virgin_bits;
    u8 *trace_bits;
    u32 share_size;
    u8 *shared_fuzz_queue_data;
    u8 *shared_stream_data;
    u32 shared_stream_used;
    u8 *shared_irq_data;
    u8 *shared_undiscovered_stream_data;

    int fd_ctl_toserver;
    int fd_ctl_fromserver;
    int fd_data_toserver;
    int fd_data_fromserver;

    u32 total_exec;

    vector<queue_entry*> *entries;
    map<u32,queue_entry*> *cksums_entries;
    vector<input_stream*> *all_streams;

    u8 *temp_compressed_bits;

    int cpu;
    int pid;
    int sync_times;

    
    map<u32,input_model*> *models;

    map<u32,u32> *streamid_mmioaddr_mapping;

    FILE *flog;

    s64 total_priority;
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
inline input_stream *allocate_new_stream(FuzzState *state,u32 id, char *file,input_stream *old , u32 len, u32 element_size)
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
input_stream *find_specific_stream(FuzzState *state,u32 id, s32 len)
{
  for(input_stream *stream : *state->all_streams)
  {
    if(*stream->stream_id == id && *stream->len == len)
      return stream;
  }
  return nullptr;
}
inline input_stream *increase_stream(FuzzState *state,input_stream *old , s32 new_len)
{
  input_stream *stream = find_specific_stream(state,*old->stream_id, new_len);
  if(!stream)
  {
    u32 old_len = *old->len;
    *old->len = new_len;
    stream = allocate_new_stream(state,*old->stream_id, nullptr, old , 0, 0);  //will copy some dirty data from shared stream, doesn't matter as long as it doesn't crash, won't
    *old->len = old_len;
  }
 
  return stream;
}

inline queue_entry* copy_queue(FuzzState *state,queue_entry* q)
{
  queue_entry *entry = new queue_entry();
  entry->fuzz_times = 0;
  entry->favorate_stream = 0;
  entry->exit_none = 0;
  entry->exit_crash = 0;
  entry->exit_outofseed = 0;
  entry->exit_timeout = 0;
  entry->exit_pc = 0;
  entry->num_mmio = 0;
  entry->cksum = 0;
  entry->edges = 0;
  entry->depth = 0;
  entry->increased = false;

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
    
    shm_id = shmget(IPC_PRIVATE, 0x1000, IPC_CREAT | IPC_EXCL | 0600);
    if (shm_id < 0) 
        fatal("shmget() failed");
    sprintf(shm_str,"%d",shm_id);
    setenv(SHM_SHARE_IRQ_VAR, shm_str, 1);
    state->shared_irq_data = (u8*)shmat(shm_id, NULL, 0);
    if (state->shared_irq_data == (void *)-1) 
        fatal("shmat() failed");

    shm_id = shmget(IPC_PRIVATE, 0x1000, IPC_CREAT | IPC_EXCL | 0600);
    if (shm_id < 0) 
        fatal("shmget() failed");
    sprintf(shm_str,"%d",shm_id);
    setenv(SHM_SHARE_UNDISCOVER_STREAM_VAR, shm_str, 1);
    state->shared_undiscovered_stream_data = (u8*)shmat(shm_id, NULL, 0);
    if (state->shared_undiscovered_stream_data == (void *)-1) 
        fatal("shmat() failed");

    shm_id = shmget(IPC_PRIVATE, 0x1000, IPC_CREAT | IPC_EXCL | 0600);
    if (shm_id < 0) 
        fatal("shmget() failed");
    sprintf(shm_str,"%d",shm_id);
    setenv(SHM_SHARE_FUZZ_QUEUE_VAR, shm_str, 1);
    state->shared_fuzz_queue_data = (u8*)shmat(shm_id, NULL, 0);
    if (state->shared_fuzz_queue_data == (void *)-1) 
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
    state->total_priority = 0;

    state->entries = new vector<struct queue_entry*>();
    state->cksums_entries = new map<u32, struct queue_entry*>();
    state->all_streams = new vector<input_stream*>();
    state->models = new map<u32,struct input_model*>();
    state->streamid_mmioaddr_mapping = new map<u32,u32>();

    state->temp_compressed_bits = (u8*)malloc(state->map_size >> 3);
    state->shared_stream_used = 0;
    state->sync_times = 0;

    sprintf(shm_str,"%s/fuzzer_log.txt",log_dir);
    state->flog = fopen(shm_str,"w");
    if(!state->flog)
      fatal("create fuzzer log file error\n");
    setbuf(state->flog,NULL);

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
  int i = 0;
  u32 *queue_ptr = (u32 *)state->shared_fuzz_queue_data;

  for(auto it = entry->streams->begin(); it != entry->streams->end(); it++)
  {
    queue_ptr[i++] = it->second->offset_to_stream_area;
  }

  queue_ptr[i] = 0xffffffff;
}
bool sync_undiscovered_streams(FuzzState *state,queue_entry* q)
{
  bool found_new_stream = false;
  uint32_t* num_new_streams = (u32*)state->shared_undiscovered_stream_data;
  uint32_t* new_streams = num_new_streams + 1;

  for(int i = 0; i < *num_new_streams ; i++)
  {
    input_stream *stream = find_specific_stream(state,new_streams[i],DEFAULT_STREAM_LEN);

    if(!stream)
      stream = allocate_new_stream(state,new_streams[i],nullptr,nullptr,DEFAULT_STREAM_LEN,DEFAULT_ELEMENT_SIZE);
    
    (*q->streams)[new_streams[i]] = stream;
  }

  return *num_new_streams;
}
void sync_irq_vals(FuzzState *state,queue_entry* q)
{
  u32* num_irq_vals = (u32 *)state->shared_irq_data;
  u16* irq_vals = (u16*)(num_irq_vals + 1);
  for(int i = 0; i < *num_irq_vals ; i++)
  {
    q->irq_vals->insert(irq_vals[i]);
  }
}
void show_stat(FuzzState *state)
{
  if(state->cpu != MAIN_CPU)
    return;
  u32 edges = count_non_255_bytes(state->virgin_bits, state->map_size);
  fprintf(stdout,"[%d][%d] total exec %d sync:%d edges:%d paths:%d used pool:%x \n",state->cpu,get_cur_time() / 1000, state->total_exec,state->sync_times, edges,state->entries->size(),state->shared_stream_used);
  fprintf(state->flog,"[%d][%d] total exec %d sync:%d edges:%d paths:%d used pool:%x \n",state->cpu,get_cur_time() / 1000, state->total_exec,state->sync_times, edges,state->entries->size(),state->shared_stream_used);
  
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
void save_stream_pool(FuzzState *state)
{
  static u32 pool_offset = 0;  // last saved pool size
  char stream_pool_filename[PATH_MAX];
  if(pool_offset == state->shared_stream_used)
    return;
  sprintf(stream_pool_filename,"%s/stream_pool.bin",queue_dir);
  FILE *f_stream = fopen(stream_pool_filename, "a");
  if(!f_stream)
    fatal("append stream file error");
  fwrite(state->shared_stream_data + pool_offset,state->shared_stream_used - pool_offset , 1, f_stream);
  fclose(f_stream);
  pool_offset = state->shared_stream_used;
}
void load_stream_pool(FuzzState *state)
{
  u32 pool_file_size;
  struct stat st;
  char stream_pool_filename[PATH_MAX];
  sprintf(stream_pool_filename,"%s/stream_pool.bin",queue_dir);
  if(access(stream_pool_filename,R_OK))
  {
    printf("no stream pool, try from stratch, in non-fuzz mode be wrong\n");
    return;
  }
  stat(stream_pool_filename, &st);
  pool_file_size = st.st_size;
  if(state->shared_stream_used >= pool_file_size)
    return;

  FILE *f_stream = fopen(stream_pool_filename, "r");
  fseek(f_stream,state->shared_stream_used,SEEK_SET);
  fread(state->shared_stream_data + state->shared_stream_used, pool_file_size - state->shared_stream_used,1,f_stream);
  state->shared_stream_used = pool_file_size;
  fclose(f_stream);
}
void save_coverage(FuzzState *state)
{
  FILE *f_coverage = fopen(coverage_file,"wb");
  fwrite(state->virgin_bits,state->map_size,1,f_coverage);
  fclose(f_coverage);
}
void save_crash(queue_entry* entry)
{
  save_entry(entry, crash_dir);
}
void save_entry(queue_entry* entry, char *folder)
{
  pthread_mutex_lock(entry_mutex);
  char entry_folder[PATH_MAX];
  char entry_streamfilename[PATH_MAX];

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


  sprintf(entry_streamfilename,"%s/%s",entry_folder, "streams.bin");
  
  FILE *f_stream = fopen(entry_streamfilename,"wb");

  if(!f_stream)
    fatal("stream file create error\n");
  

  for (auto it = entry->streams->begin(); it != entry->streams->end(); it++)
  {
    fwrite(&it->second->offset_to_stream_area,sizeof(it->second->offset_to_stream_area),1,f_stream);
  }
  fclose(f_stream);
  closedir(dir);
  pthread_mutex_unlock(entry_mutex);

}

queue_entry* load_entry(FuzzState *state,u32 id, char *entry_dir)
{
  char entry_folder[PATH_MAX];
  char entry_streamfilename[PATH_MAX];
  struct stat st;
  u32 num_streams;
  u32 stream_offset;
  queue_entry *entry = copy_queue(state,nullptr);

  sprintf(entry_folder,"%s/%08x",entry_dir, id);
  sprintf(entry_streamfilename,"%s/%s",entry_folder, "streams.bin");


  FILE *f = fopen(entry_streamfilename,"rb");
  if(f == NULL)
    fatal("stream file open error\n");
    
  
  stat(entry_streamfilename, &st);
  num_streams = st.st_size / sizeof(u32);
  for(u32 i = 0; i < num_streams; i++)
  {
    fread(&stream_offset, sizeof(u32), 1, f);
    input_stream *stream = new input_stream();
    stream->offset_to_stream_area = stream_offset;
    stream->ptr = state->shared_stream_data + stream->offset_to_stream_area;
    stream->stream_id = (u32 *)stream->ptr;
    stream->len = (s32*)(stream->ptr + sizeof(*stream->stream_id));
    stream->mode = (u32*)(stream->ptr + sizeof(*stream->stream_id) + sizeof(*stream->len));
    stream->element_size = (s32*)(stream->ptr + sizeof(*stream->stream_id) + sizeof(*stream->len) + sizeof(*stream->mode));
    stream->left_shift = (s32*)(stream->ptr + sizeof(*stream->stream_id) + sizeof(*stream->len) + sizeof(*stream->mode) + sizeof(*stream->element_size));
    stream->data = (u8*)(stream->ptr + sizeof(*stream->stream_id) + sizeof(*stream->len) + sizeof(*stream->mode) + sizeof(*stream->element_size) + sizeof(*stream->left_shift));
    (*entry->streams)[*stream->stream_id] = stream;
  }
  fclose(f);
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
        out.push_back(q);
      }
    }
  }
  closedir(dir);
  
  pthread_mutex_unlock(entry_mutex);
  if(state->entries->size() == 0)
  {
    queue_entry *q = copy_queue(state,nullptr);
    #ifdef ENABLE_IRQ
    input_stream *stream = allocate_new_stream(state,IRQ_STREAM_ID,nullptr,nullptr,DEFAULT_STREAM_LEN,DEFAULT_IRQ_ELEMENT_SIZE);  //irq always there
    (*q->streams)[IRQ_STREAM_ID] = stream;
    #endif
    out.push_back(q);
  }
  for(queue_entry * q : out)
  {
    find_all_streams_save_queue(state,q);
    show_stat(state);
  }
  
  printf("-------------------sync entry finish----------------------\n");
}

void run_modelling(FuzzState *state)
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
    if (dir_entry->d_type == DT_REG  && strstr(dir_entry->d_name,"state_model_")) 
    {
      u32 id = strtol(dir_entry->d_name + strlen("state_model_"),0,16);
      if(state->models->find(id) == state->models->end())
      {
        printf("start model file:%s\n",dir_entry->d_name);
        sprintf(cmd,"%s/run_docker.sh %s fuzzware model ./state/%s -c ./model/model.yml > /dev/null","/home/w/hd/iofuzzer/fuzzware",out_dir,dir_entry->d_name);
        system(cmd);
        printf("model file done:%s\n",dir_entry->d_name);
      }
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

s32 fuzz_one(FuzzState *state,queue_entry* entry,u32* exit_info, u32* exit_pc)
{
  s32 exit_code;
  memset(state->trace_bits,0,state->map_size);
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
    run_modelling(state);
    sync_models(state);
    #ifdef ENABLE_IRQ
    sync_irq_vals(state,entry);
    #endif
    found_new_streams = sync_undiscovered_streams(state,entry);
    
  }while(found_new_streams);

  classify_counts((u64*)state->trace_bits,state->map_size);
  has_new_bits_update_virgin(state->virgin_bits, state->trace_bits, state->map_size);
  entry->edges = count_bytes(state->trace_bits, state->map_size);
  // minimize_bits(state->temp_compressed_bits,state->trace_bits,state->map_size);
  // entry->cksum = hash32(state->temp_compressed_bits,state->map_size >> 2);
  entry->cksum = hash32(state->trace_bits,state->map_size);
  entry->exit_pc = exit_pc;
  entry->priority = entry->streams->size() + entry->edges * entry->depth;
  state->total_priority += entry->priority;
  state->entries->push_back(entry);
  
  (*state->cksums_entries)[entry->cksum] = entry;

  save_stream_pool(state);

  save_entry(entry,queue_dir);


}
void fuzz_one_post(FuzzState *state,queue_entry* entry, input_stream *fuzzed_stream, s32 exit_code, u32 exit_info, u32 exit_pc)
{

  
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
    fuzzed_stream->priority += 1;
    queue_entry* q = copy_queue(state,entry);
    q->depth++;
    find_all_streams_save_queue(state,q);
    (*q->streams)[*fuzzed_stream->stream_id] = allocate_new_stream(state,*fuzzed_stream->stream_id,nullptr,fuzzed_stream,0,0);
    show_stat(state);
    if(unlikely(r == 2))
    {
      save_coverage(state);
      fuzzed_stream->priority += 4;
    }
  
  }


}



#define FLIP_BIT(_ar, _b) do { \
    u8* _arf = (u8*)(_ar); \
    u32 _bf = (_b); \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf) & 7)); \
  } while (0)
void havoc(FuzzState *state,queue_entry* q, input_stream* stream)
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
void havoc_entry(FuzzState *state,queue_entry* q)
{
  // for(auto it = q->streams->begin(); it != q->streams->end(); it++)
  // {
  //   havoc(state,it->second);
  // }
}
queue_entry* select_entry(FuzzState *state)
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
void fuzz_loop(FuzzState *state, int cpu)
{ 
    u64 rounds = 0;
    u32 exit_info,exit_pc;
    s32 exit_code;
    s32 len;
    u32 i;
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

        for(auto it = entry->streams->begin() ; it != entry->streams->end() ; it++)
        {
          if(*it->second->mode == MODEL_CONSTANT || *it->second->mode == MODEL_PASSTHROUGH)
            continue;
          len = *it->second->len; 
          for(i = 0 ; i < it->second->priority ; i++)
          {
            memcpy(org_buf, it->second->data, len);

            havoc(state,entry, it->second);

            exit_code = fuzz_one(state,entry,&exit_info,&exit_pc);

            fuzz_one_post(state,entry,it->second, exit_code,exit_info,exit_pc);

            memcpy(it->second->data, org_buf, len); 
          } 
          
        }  

      }

      rounds++;
      show_stat(state);
      // if((rounds & 0xfff) == 0)
      //   sync_entries(state);
      
      
    
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
  load_stream_pool(state);
  queue_entry* entry = load_entry(state,id, queue_dir);
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
  sprintf(coverage_file,"%s/coverage.bin",out_dir);

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
      fuzzer_init(&state,FUZZ_COVERAGE_SIZE, SHARE_FUZZDATA_SIZE);

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
  fuzzer_init(&state,FUZZ_COVERAGE_SIZE, SHARE_FUZZDATA_SIZE);
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

  fuzzer_init(&state,FUZZ_COVERAGE_SIZE, SHARE_FUZZDATA_SIZE);
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

