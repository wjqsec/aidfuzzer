#include <vector>
#include <set>
#include <map>
#include <poll.h>
#include <sched.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <algorithm>         /* Definition of AT_* constants */
#include <random>
#include <sys/syscall.h>      /* Definition of SYS_* constants */
#include <dirent.h>
#include <sys/time.h>
#include <linux/limits.h>
#include <sys/shm.h>
#include <fcntl.h>              /* Definition of O_* constants */
#include <sys/stat.h>
#include <execinfo.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#define SHM_ENV_VAR         "__AFL_SHM_ID"
#define SHM_SHARE_VAR         "__AFL_SHM_SHARE"
#define likely(_x)   __builtin_expect(!!(_x), 1)
#define unlikely(_x)  __builtin_expect(!!(_x), 0)

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t  u64;

typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;
using namespace std;


#define EXIT_NONE 0
#define EXIT_TIMEOUT 1
#define EXIT_OUTOFSEED 2
#define EXIT_CRASH 3

#define FORKSRV_CTLFD          198
#define FORKSRV_DATAFD          200

#define FUZZ_REQ 0x1
#define CMP_VAL 0x2
#define FUZZ_OUTPUT 0x3
#define ACK 0x4

#define DEFAULT_STREAM_LEN 0x100
#define MAX_STREAM_LEN 0x1000000


#define INTERESTING_8 \
  -128,          /* Overflow signed 8-bit when decremented  */ \
  -1,            /*                                         */ \
   0,            /*                                         */ \
   1,            /*                                         */ \
   16,           /* One-off with common buffer size         */ \
   32,           /* One-off with common buffer size         */ \
   64,           /* One-off with common buffer size         */ \
   100,          /* One-off with common buffer size         */ \
   127           /* Overflow signed 8-bit when incremented  */

#define INTERESTING_16 \
  -32768,        /* Overflow signed 16-bit when decremented */ \
  -129,          /* Overflow signed 8-bit                   */ \
   128,          /* Overflow signed 8-bit                   */ \
   255,          /* Overflow unsig 8-bit when incremented   */ \
   256,          /* Overflow unsig 8-bit                    */ \
   512,          /* One-off with common buffer size         */ \
   1000,         /* One-off with common buffer size         */ \
   1024,         /* One-off with common buffer size         */ \
   4096,         /* One-off with common buffer size         */ \
   32767         /* Overflow signed 16-bit when incremented */

#define INTERESTING_32 \
  -2147483648LL, /* Overflow signed 32-bit when decremented */ \
  -100663046,    /* Large negative number (endian-agnostic) */ \
  -32769,        /* Overflow signed 16-bit                  */ \
   32768,        /* Overflow signed 16-bit                  */ \
   65535,        /* Overflow unsig 16-bit when incremented  */ \
   65536,        /* Overflow unsig 16 bit                   */ \
   100663045,    /* Large positive number (endian-agnostic) */ \
   2147483647    /* Overflow signed 32-bit when incremented */

#define HASH_CONST          0xa5b35705
static s8  interesting_8[]  = { INTERESTING_8 };
static s16 interesting_16[] = { INTERESTING_8, INTERESTING_16 };
static s32 interesting_32[] = { INTERESTING_8, INTERESTING_16, INTERESTING_32 };
u8 count_class_lookup8[256];

u16 count_class_lookup16[65536];

void fatal(const char *msg)
{
    printf("%s",msg);
    fflush(stdout);
    exit(0);
}

void init_count_class16(void) {
  count_class_lookup8[0] = 0;
  count_class_lookup8[1] = 1;
  count_class_lookup8[2] = 2;
  count_class_lookup8[3] = 4;
  int i;
  
  for(i = 4;i <= 7; i++)
    count_class_lookup8[i] = 8;
  for(i = 8;i <= 15; i++)
    count_class_lookup8[i] = 16;
  for(i = 16;i <= 31; i++)
    count_class_lookup8[i] = 32;
  for(i = 32;i <= 127; i++)
    count_class_lookup8[i] = 64;
  for(i = 128;i <= 255; i++)
    count_class_lookup8[i] = 128;
  

  u32 b1, b2;

  for (b1 = 0; b1 < 256; b1++) 
    for (b2 = 0; b2 < 256; b2++)
      count_class_lookup16[(b1 << 8) + b2] = 
        (count_class_lookup8[b1] << 8) |
        count_class_lookup8[b2];

}
inline void classify_counts(u64* mem, u32 size) {

  u32 i = size >> 3;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) {

      u16* mem16 = (u16*)mem;

      mem16[0] = count_class_lookup16[mem16[0]];
      mem16[1] = count_class_lookup16[mem16[1]];
      mem16[2] = count_class_lookup16[mem16[2]];
      mem16[3] = count_class_lookup16[mem16[3]];

    }

    mem++;

  }

}
inline u8 has_new_bits_update_virgin(u8* virgin_map, u8 *trace_bits, u32 size) 
{
  u64* current = (u64*)trace_bits;
  u64* virgin  = (u64*)virgin_map;

  u32  i = (size >> 3);

  u8   ret = 0;

  while (i--) {

    if (unlikely(*current) && unlikely(*current & *virgin)) {

      if (likely(ret < 2)) {

        u8* cur = (u8*)current;
        u8* vir = (u8*)virgin;

        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff) ||
            (cur[4] && vir[4] == 0xff) || (cur[5] && vir[5] == 0xff) ||
            (cur[6] && vir[6] == 0xff) || (cur[7] && vir[7] == 0xff)) ret = 2;
        else ret = 1;

      }

      *virgin &= ~*current;

    }

    current++;
    virgin++;

  }

  return ret;

}
inline u32 count_bits(u8* mem, u32 size) {

  u32* ptr = (u32*)mem;
  u32  i   = (size >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    if (v == 0xffffffff) {
      ret += 32;
      continue;
    }

    v -= ((v >> 1) & 0x55555555);
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
    ret += (((v + (v >> 4)) & 0xF0F0F0F) * 0x01010101) >> 24;

  }

  return ret;

}
inline u32 count_bytes(u8* mem, u32 size) {

#define FF(_b)  (0xff << ((_b) << 3))
  u32* ptr = (u32*)mem;
  u32  i   = (size >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    if (!v) continue;
    if (v & FF(0)) ret++;
    if (v & FF(1)) ret++;
    if (v & FF(2)) ret++;
    if (v & FF(3)) ret++;

  }

  return ret;
}
inline u32 count_non_255_bytes(u8* mem, u32 size) {

  u32* ptr = (u32*)mem;
  u32  i   = (size >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    /* This is called on the virgin bitmap, so optimize for the most likely
       case. */

    if (v == 0xffffffff) continue;
    if ((v & FF(0)) != FF(0)) ret++;
    if ((v & FF(1)) != FF(1)) ret++;
    if ((v & FF(2)) != FF(2)) ret++;
    if ((v & FF(3)) != FF(3)) ret++;

  }

  return ret;

}
#define ROL64(_x, _r)  ((((u64)(_x)) << (_r)) | (((u64)(_x)) >> (64 - (_r))))
inline u32 hash32(const void* key, u32 len) 
{

  const u64* data = (u64*)key;
  u64 h1 = HASH_CONST ^ len;

  len >>= 3;

  while (len--) {

    u64 k1 = *data++;

    k1 *= 0x87c37b91114253d5ULL;
    k1  = ROL64(k1, 31);
    k1 *= 0x4cf5ad432745937fULL;

    h1 ^= k1;
    h1  = ROL64(h1, 27);
    h1  = h1 * 5 + 0x52dce729;

  }

  h1 ^= h1 >> 33;
  h1 *= 0xff51afd7ed558ccdULL;
  h1 ^= h1 >> 33;
  h1 *= 0xc4ceb9fe1a85ec53ULL;
  h1 ^= h1 >> 33;

  return h1;
}

inline void minimize_bits(u8* dst, u8* src, u32 size) {

  u32 i = 0;

  while (i < size) {

    if (*(src++)) dst[i >> 3] |= 1 << (i & 7);
    i++;
  }

}
inline u32 UR(u32 limit) {

  #define RESEED_RNG          10000
  static u32 rand_cnt = 0;
  if (unlikely(!rand_cnt--)) {

    u32 seed[2];

    FILE *f = fopen("/dev/urandom","rb");
    if(!f)
      fatal("open random file error\n");
    fread(seed,sizeof(seed),1,f);
    fclose(f);
    srandom(seed[0]);
    rand_cnt = (RESEED_RNG / 2) + (seed[1] % RESEED_RNG);
  }

  return random() % limit;

}

// does d2 totally cover d1?
inline static bool cover_all_bits(u8* d1, u8* d2, u32 size)
{
  u32* s1 = (u32*)d1;
  u32* s2  = (u32*)d2;
  u32 j = size >> 2;
  for(u32 i = 0; i < j ; i++ )
  {
    if((s1[i] | s2[i]) != s2[i])
    {
      //printf("return false %d  %x  %x  %x  %d\n",i,s1[i],s2[i],s1[i] | s2[i],(s1[i] | s2[i]) != s2[i]);
      return false;
    }
  }
  return true;
}
inline static u64 get_cur_time(void) {

  struct timeval tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);

}
void handler(int sig) {
  void *array[10];
  size_t size;

  // get void*'s for all entries on the stack
  size = backtrace(array, 10);

  // print out all the frames to stderr
  fprintf(stderr, "Error: signal %d:\n", sig);
  backtrace_symbols_fd(array, size, STDERR_FILENO);
  exit(1);
}


struct input_stream
{
    u32 id;
    u8 *data;
    s32 len;
    s32 used;
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
    u8 *shared_data;

    int fd_ctl_toserver;
    int fd_ctl_fromserver;
    int fd_data_toserver;
    int fd_data_fromserver;
    struct pollfd pfds[2];

    u32 total_exec;

    vector<queue_entry*> *entries;
    map<u32,queue_entry*> *cksums_entries;
    set<u32> *cksums;
    u8 *temp_compressed_bits;

    int cpu;
    int pid;
    int sync_times;

    set<u16> *interesting_vals;
};

#define ENTRY_MUTEX_MEM_SIZE 1024
#define ENTRY_MUTEX_KEY 1234
pthread_mutex_t *entry_mutex;
char *in_dir, *out_dir;


s32 fuzz_one(FuzzState *state,queue_entry* entry,u32* exit_info, u32* exit_pc);
void free_queue(queue_entry* q);
bool fuzz_one_post(FuzzState *state,queue_entry* entry, s32 exit_code, u32 exit_info, u32 exit_pc);
void reset_queue(queue_entry* q);
void save_entry(queue_entry* entry, char *folder);


inline input_stream *new_stream(u32 id, char *file)
{
  input_stream *stream = new input_stream();
  stream->id = id;
  stream->used = 0;

  if(file)
  {
    struct stat st;
    if (lstat(file, &st) || access(file, R_OK))
    {
      fatal("unable to access backup file\n");
    }
    FILE *fd = fopen(file,"rb");
    stream->len = st.st_size;
    stream->data = (u8*)malloc(stream->len);
    
    fread(stream->data,stream->len,1,fd);
    fclose(fd);
  }
  else
  {
    // if(id == 0x40013800 || id == 0x40004400)
    // {
    //   stream->data = (u8*)malloc(DEFAULT_STATUS_STREAM_LEN);
    //   stream->len = DEFAULT_STATUS_STREAM_LEN;
    //   memset(stream->data,0x80,stream->len);
    // }
    // else
    {
      stream->data = (u8*)malloc(DEFAULT_STREAM_LEN);
      stream->len = DEFAULT_STREAM_LEN;
      for(int i = 0 ; i < (stream->len >> 2) ; i++)
        ((u32*)stream->data)[i] = UR(0XFFFFFFFF);
    }
    
  }
  return stream;
}
queue_entry* copy_queue(queue_entry* q)
{
  queue_entry *entry = new queue_entry();
  entry->streams = new map<u32,input_stream *>();
  if(q)
  {
    for (auto it = q->streams->begin(); it != q->streams->end(); it++)
    {
      input_stream *stream = new input_stream();
      stream->id = it->second->id;
      stream->len = it->second->len;
      stream->used = 0;
      stream->data = (u8*)malloc(stream->len);
      memcpy(stream->data,it->second->data,stream->len);
      entry->streams->insert({it->first , stream});
    }
    entry->depth = q->depth + 1;
    entry->exit_pc = q->exit_pc;
  }
  else
  {
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
    setenv(SHM_SHARE_VAR, shm_str, 1);
    state->shared_data = (u8*)shmat(shm_id, NULL, 0);
    if (state->shared_data == (void *)-1) 
        fatal("shmat() failed");
    

    int st_pipe[2], ctl_pipe[2], todata_pipe[2], fromdata_pipe[2];
    if (pipe(st_pipe) || pipe(ctl_pipe) || pipe(todata_pipe) || pipe(fromdata_pipe)) fatal("pipe() failed");
    if (dup2(ctl_pipe[0], FORKSRV_CTLFD) < 0) fatal("dup2() failed");
    if (dup2(st_pipe[1], FORKSRV_CTLFD + 1) < 0) fatal("dup2() failed");
    if (dup2(todata_pipe[0], FORKSRV_DATAFD) < 0) fatal("dup2() failed");
    if (dup2(fromdata_pipe[1], FORKSRV_DATAFD + 1) < 0) fatal("dup2() failed");
    state->fd_ctl_toserver = ctl_pipe[1];
    state->fd_ctl_fromserver = st_pipe[0];
    state->fd_data_toserver = todata_pipe[1];
    state->fd_data_fromserver = fromdata_pipe[0];
    
    state->total_exec = 0;

    state->pfds[0].fd = state->fd_ctl_fromserver;
    state->pfds[0].events = POLLIN;
    state->pfds[1].fd = state->fd_data_fromserver;
    state->pfds[1].events = POLLIN;

    state->entries = new vector<struct queue_entry*>();
    state->cksums = new set<u32>();
    state->cksums_entries = new map<u32, struct queue_entry*>();
    state->temp_compressed_bits = (u8*)malloc(state->map_size >> 3);

    state->sync_times = 0;

    state->interesting_vals = new set<u16>();

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
    read(state->fd_ctl_fromserver, buf,16);
    *exit_info = buf[1];
    *exit_pc = buf[2];
    *num_mmio = buf[3];
    return buf[0];
}


int run_controlled_process(int argc,char *old_argv[])
{
	pid_t pid;
	char *child_arg[1000];
	int i;
	for(i= 3; i<argc;i++) 
		child_arg[i-3] = old_argv[i];
	child_arg[i-3] = NULL;
	pid = fork();
	if (pid < 0) fatal("fork error\n");
	else if(!pid)
	{
		execv(child_arg[0],child_arg);
	}
  return pid;
}

void copy_fuzz_data(FuzzState *state,queue_entry* entry,u32** num_new_streams,u32** new_streams)
{
  u32* num_streams_ptr = (u32*)state->shared_data;
  *num_streams_ptr = entry->streams->size();
  u8 *ptr = state->shared_data + 4;
  for (auto it = entry->streams->begin(); it != entry->streams->end(); it++)
  {
    
    *(uint32_t*)ptr = it->second->id;
    *(uint32_t*)(ptr+4) = it->second->len;
    *(uint32_t*)(ptr+8) = it->second->used;
    memcpy(ptr+12,it->second->data,it->second->len);
    ptr += 12 + it->second->len;

    
  }
  *num_new_streams = (u32*)ptr;
  *new_streams = (u32*)(ptr + 4);
  
}
void sync_undiscovered_streams(queue_entry* entry,u32* num_new_streams,u32* new_streams)
{
  for(int i = 0; i < *num_new_streams ; i++)
  {
    input_stream *stream = new_stream(new_streams[i],nullptr);
    entry->streams->insert({new_streams[i] , stream});
  }
}
void sync_interesting_vals(FuzzState *state,u32* num_interesting_vals,u16* interesting_vals)
{
  for(int i = 0; i < *num_interesting_vals ; i++)
  {
    state->interesting_vals->insert(interesting_vals[i]);
  }
}
void show_stat(FuzzState *state)
{
  if(state->cpu != 0)
    return;
  u32 edges = count_non_255_bytes(state->virgin_bits, state->map_size);
  printf("[%d][%d] total exec %d sync:%d edges:%d paths:%d\n",state->cpu,get_cur_time() / 1000, state->total_exec,state->sync_times, edges,state->entries->size());
  printf("-----------queue details-----------\n");
  printf("id        depth     bbls      #streams  prio      favorate  none      seed      timeout   crash     exit_pc   num_mmio  exec_times\n");
  //int count = state->cksums_entries->size();
  for (auto it = state->cksums_entries->begin(); it != state->cksums_entries->end(); it++)
  {
    printf("%-10x%-10d%-10d%-10d%-10d%-10x%-10d%-10d%-10d%-10d%-10x%-10d%-10d\n",
    it->second->cksum,
    it->second->depth,
    it->second->edges,
    it->second->streams->size(),
    it->second->priority,
    it->second->favorate_stream ? it->second->favorate_stream : 0,
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
  save_entry(entry, out_dir);
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

  sprintf(entry_folder,"%s/%x",folder, entry->cksum);
  mkdir(entry_folder, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  sprintf(entry_metafilename,"%s/%s",entry_folder, "meta.data");
  
  FILE *f = fopen(entry_metafilename,"wb");
  if(!f)
    fatal("meta file open error\n");
  fclose(f);

  for (auto it = entry->streams->begin(); it != entry->streams->end(); it++)
  {
    sprintf(entry_filename,"%s/%x",entry_folder,it->second->id);
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
queue_entry* load_entry(u32 id)
{
  char entry_filename[PATH_MAX];
  char entry_folder[PATH_MAX];
  char entry_metafilename[PATH_MAX];
  queue_entry *entry = copy_queue(nullptr);

  sprintf(entry_folder,"%s/%x",in_dir, id);
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
      sprintf(entry_filename,"%s/%x",entry_folder,stream_id);
      input_stream *tmp = new_stream(stream_id,entry_filename);
      (*entry->streams)[stream_id] = tmp;  
    }
  }
  closedir(dir);
  return entry;
}
void sync_entries(FuzzState *state)
{
  pthread_mutex_lock(entry_mutex);
  vector<queue_entry *> out;
  DIR* dir;
  u32 exit_info,exit_pc;
  s32 exit_code;
  struct dirent* dir_entry;

  dir = opendir(in_dir);
  if (dir == NULL)
      fatal("opendir error");

  while ((dir_entry = readdir(dir)) != NULL) 
  {
    if (dir_entry->d_type == DT_DIR && strcmp(dir_entry->d_name,".") && strcmp(dir_entry->d_name,"..")) 
    {
      u32 entry_id = strtol(dir_entry->d_name,0,16);
      if(state->cksums->find(entry_id) == state->cksums->end())
      {
        out.push_back(load_entry(entry_id));
      }
    }
  }
  closedir(dir);
  pthread_mutex_unlock(entry_mutex);
  state->sync_times++;

  if(out.size() == 0)
    out.push_back(copy_queue(nullptr));

  for(queue_entry *entry : out)
  {

    exit_code = fuzz_one(state,entry,&exit_info,&exit_pc);
    fuzz_one_post(state,entry,exit_code,exit_info,exit_pc);

    free_queue(entry);

  }

  
}
void try_increased_stream(FuzzState *state,queue_entry* entry,input_stream *stream)
{

  s32 old_len = stream->len;
  u32 exit_info,exit_pc;
  s32 exit_code;
  int found_new = 0;

  s32 len = old_len << 1;
  if(len >= MAX_STREAM_LEN)
    return;
  stream->data = (u8*)realloc(stream->data,len);
  stream->len = len;
  for(int i = (old_len >> 2) ; i < (len >> 2) ; i++)
  {
    ((u32*)stream->data)[i] = UR(0XFFFFFFFF);
  }

  exit_code = fuzz_one(state,entry,&exit_info,&exit_pc);

  found_new = fuzz_one_post(state,entry,exit_code,exit_info,exit_pc);

  if(!found_new)
  {
    stream->data =  (u8*)realloc(stream->data,old_len);
    stream->len = old_len;
  }


}
s32 fuzz_one(FuzzState *state,queue_entry* entry,u32* exit_info, u32* exit_pc)
{
  s32 exit_code;
  u32* num_new_streams;
  u32* new_streams;
  u32* num_interesting_vals;
  u16* interesting_vals;
  memset(state->trace_bits,0,state->map_size);
  reset_queue(entry);
  copy_fuzz_data(state,entry,&num_new_streams,&new_streams);
  num_interesting_vals = (u32*)(((u8*)num_new_streams) + 500);
  interesting_vals = (u16*)(num_interesting_vals + 1);
  fork_server_runonce(state);
  exit_code = fork_server_getexit(state,exit_info,exit_pc,&entry->num_mmio);
  sync_undiscovered_streams(entry,num_new_streams,new_streams);
  sync_interesting_vals(state,num_interesting_vals,interesting_vals);
  return exit_code;
  
}
bool fuzz_one_post(FuzzState *state,queue_entry* entry, s32 exit_code, u32 exit_info, u32 exit_pc)
{

  classify_counts((u64*)state->trace_bits,state->map_size);
  int r = has_new_bits_update_virgin(state->virgin_bits, state->trace_bits, state->map_size);
  state->total_exec++;
  entry->exit_pc = exit_pc;
  entry->fuzz_times++;

  if(exit_code == EXIT_CRASH)
  {
    entry->exit_crash++;
    save_crash(entry);
    return false;
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
    if(exit_info != 0)
    {
      entry->favorate_stream = exit_info;
    }
  }
  
  if(unlikely(r))
  {
    queue_entry* q = copy_queue(entry);
    q->edges = count_bytes(state->trace_bits, state->map_size);
    minimize_bits(state->temp_compressed_bits,state->trace_bits,state->map_size);
    q->cksum = hash32(state->temp_compressed_bits,state->map_size >> 2);
    state->entries->push_back(q);
    state->cksums_entries->insert({q->cksum , q});
    save_entry(q,in_dir);
    state->cksums->insert(q->cksum);
    
    if(unlikely(r == 2))
      show_stat(state);
    return true;
  }
  
  return false;
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
  u32 use_stacking = 1 + UR(stream->len >> 2);
  s32 len = stream->len;
  u8 *data = stream->data;
  if(len  <= 8 )
    return;

  for (s32 i = 0; i < use_stacking; i++) 
  {
    if(stream->id == 0xffffffff)   //for irq
    {
      if(state->interesting_vals->size() == 0)
          break;
      auto it = state->interesting_vals->begin();
      std::advance(it, UR(state->interesting_vals->size()));
      u16* tmp = (u16*)(data + (UR(len - 1) & 0xfffffffe));
      *tmp = *it;
    }
    else
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
queue_entry* select_entry(FuzzState *state)
{
  s32 total_priority = 0;
  for(int i = 0; i < state->entries->size(); i++)
  {
    (*state->entries)[i]->priority = (*state->entries)[i]->streams->size() == 0 ? 1 : (*state->entries)[i]->streams->size(); //+ ((*state->entries)[i]->edges / 10);
    (*state->entries)[i]->priority += (*state->entries)[i]->edges / 10;
    if((*state->entries)[i]->exit_outofseed > (*state->entries)[i]->exit_timeout)
      (*state->entries)[i]->priority *= 1.2;
    total_priority += (*state->entries)[i]->priority;
  }

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
          
          s32 len = stream->len;  
          memcpy(org_buf, stream->data, len);
          havoc(state, stream);

          exit_code = fuzz_one(state,entry,&exit_info,&exit_pc);
          fuzz_one_post(state,entry,exit_code,exit_info,exit_pc);

          memcpy(stream->data, org_buf, len); 
          if(exit_code == EXIT_OUTOFSEED)
            try_increased_stream(state,entry,(*entry->streams)[exit_info]);
        }

        rounds++;   
      }
      if((rounds & 0xfff) == 0)
        sync_entries(state);
      if((rounds & 0xff) == 0)
        show_stat(state);
    }
    
}
void reproduce_crash(FuzzState *state, u32 id)
{
  fork_server_up(state);
  char entry_filename[PATH_MAX];
  char entry_folder[PATH_MAX];
  char entry_metafilename[PATH_MAX];
  u32 exit_info,exit_pc;
  s32 exit_code;
  queue_entry* entry = copy_queue(nullptr);
  sprintf(entry_folder,"%s/%x",out_dir, id);

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
      sprintf(entry_filename,"%s/%x",entry_folder,stream_id);
      input_stream *tmp = new_stream(stream_id,entry_filename);
      (*entry->streams)[stream_id] = tmp;  
    }
  }
  exit_code = fuzz_one(state,entry,&exit_info,&exit_pc);
  printf("exit code :%d\n",exit_code);

}
void init_dir(int argc, char **argv)
{
  if(argc >= 4)
  {
    in_dir = strdup(argv[1]);
    out_dir = strdup(argv[2]);
  }
  else
  {
    printf("Usage: %s [%s] [%s] [%s] ...\n",argv[0], "in_dir", "out_dir","bin");
    exit(0);
  }
  mkdir(in_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  mkdir(out_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
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
  init_dir(argc,argv);
  init_shared_mutex();
  init_count_class16();
  
  long number_of_processors = sysconf(_SC_NPROCESSORS_ONLN);
  //long number_of_processors = 1;
  for(int i = 0; i < number_of_processors; i++)
  {
    int pid = fork();
    if(pid == -1)
      fatal("fork error\n");
    else if(pid == 0)
    {
      FuzzState state;
      fuzzer_init(&state,1 << 16, 100 << 20);
      int pid = run_controlled_process(argc,argv);
      state.pid = pid;
      fuzz_loop(&state,i);
    }
  }
  wait(&status);
  return 1;

}
int test_crash(int argc, char **argv)
{
  init_dir(argc,argv);
  init_shared_mutex();
  init_count_class16();
  FuzzState state;
  fuzzer_init(&state,1 << 16, 100 << 20);
  int pid = run_controlled_process(argc,argv);
  state.pid = pid;
  reproduce_crash(&state, 0x102214a5);
  kill(pid,9);
  return 1;

}
int main(int argc, char **argv)
{
  return test_crash(argc, argv);
  //return fuzz(argc, argv);
}

