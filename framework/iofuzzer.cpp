#include <vector>
#include <set>
#include <map>
#include <poll.h>

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <algorithm>
#include <fcntl.h>            /* Definition of AT_* constants */
#include <random>
#include <sys/syscall.h>      /* Definition of SYS_* constants */

#include <sys/time.h>
#include <linux/limits.h>
#include <sys/shm.h>
#include <fcntl.h>              /* Definition of O_* constants */
#include <sys/types.h>
#include <sys/stat.h>


#define SHM_ENV_VAR         "__AFL_SHM_ID"
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
#define DEFAULT_STATUS_STREAM_LEN 0x100000
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

static s8  interesting_8[]  = { INTERESTING_8 };
static s16 interesting_16[] = { INTERESTING_8, INTERESTING_16 };
static s32 interesting_32[] = { INTERESTING_8, INTERESTING_16, INTERESTING_32 };
u8 count_class_lookup8[256];

u16 count_class_lookup16[65536];

void fatal(const char *msg)
{
    printf("%s",msg);
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

struct input_stream
{
    char *backup_file;
    u32 id;
    u8 *data;
    s32 len;
    s32 used;
    set<u32> *interesting_vals;
};

struct queue_entry
{
    int id;
    u64 exec_time;
    u32 edges;
    u32 fuzz_times;
    s32 depth;
    map<u32,input_stream *> *streams;
    input_stream * favorate_stream;
    u32 exit_pc;
    //vector<u32> *stream_order;
    //u8 *compressed_bits
    u32 exit_none;
    u32 exit_outofseed;
    u32 exit_timeout;
    u32 exit_crash;

    u32 num_mmio;
    u32 exit_seed;
    
#define DEFAULT_PRIORITY 1
    s32 priority;

};
struct FuzzState
{
    u32 map_size;
    u8 *virgin_bits;
    u8 *trace_bits;

    int fd_ctl_toserver;
    int fd_ctl_fromserver;
    int fd_data_toserver;
    int fd_data_fromserver;
    struct pollfd pfds[2];

    u32 total_exec;
    u32 total_edges;

    // u32 exit_none;
    // u32 exit_outofseed;
    // u32 exit_timeout;
    // u32 exit_crash;

    vector<queue_entry*> *entries;

    s32 total_priority;
};


inline input_stream *new_stream(u32 id, char *file)
{
  input_stream *stream = new input_stream();
  stream->id = id;
  stream->used = 0;
  stream->interesting_vals = new set<u32>();
  if(file)
  {
    struct stat st;
    stream->backup_file = strdup(file);
    if (lstat(file, &st) || access(file, R_OK))
    {
      fatal("unable to access backup file\n");
    }
    FILE *fd = fopen("file","rb");
    stream->len = st.st_size > MAX_STREAM_LEN ? MAX_STREAM_LEN : st.st_size;
    stream->data = (u8*)malloc(stream->len);
    
    fread(stream->data,stream->len,1,fd);
    fclose(fd);
  }
  else
  {
    stream->backup_file = 0;
    if(id == 0x40013800 || id == 0x40004400)
    {
      stream->data = (u8*)malloc(DEFAULT_STATUS_STREAM_LEN);
      stream->len = DEFAULT_STATUS_STREAM_LEN;
      memset(stream->data,0x80,stream->len);
    }
    else
    {
      stream->data = (u8*)malloc(DEFAULT_STREAM_LEN);
      stream->len = DEFAULT_STREAM_LEN;
      memset(stream->data,0x80,stream->len);
    }
    
  }
  return stream;
}
queue_entry* copy_queue(FuzzState *state,queue_entry* q)
{
  static int id = 0;
  queue_entry *entry = new queue_entry();
  entry->streams = new map<u32,input_stream *>();

  if(q)
  {
    for (auto it = q->streams->begin(); it != q->streams->end(); it++)
    {
      input_stream *stream = new input_stream();
      stream->backup_file = it->second->backup_file;
      stream->id = it->second->id;
      stream->len = it->second->len;
      stream->used = 0;
      stream->data = (u8*)malloc(stream->len);
      stream->interesting_vals = it->second->interesting_vals;
      memcpy(stream->data,it->second->data,stream->len);
      entry->streams->insert({it->first , stream});
    }
    entry->depth = q->depth + 1;
  }
  else
  {
    entry->depth = 0;
  }
  

  //entry->stream_order = new vector<u32>(*q->stream_order);
  //entry->compressed_bits = (u8*)malloc(state->map_size >> 3);
  //memset(entry->compressed_bits,0,state->map_size >> 3);
  

  
  entry->fuzz_times = 0;
  entry->favorate_stream = nullptr;
  entry->exit_none = 0;
  entry->exit_crash = 0;
  entry->exit_outofseed = 0;
  entry->exit_timeout = 0;
  entry->id = id++;
  entry->num_mmio = 0;
  entry->exit_seed = 0;
  return entry;
}



void fuzzer_init(FuzzState *state, u32 map_size) 
{
    char shm_str[PATH_MAX];
    state->map_size = map_size;
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
    state->entries = new vector<struct queue_entry*>();

    state->total_exec = 0;
    state->total_edges = 0;
    // state->exit_none = 0;
    // state->exit_outofseed = 0;
    // state->exit_timeout = 0;
    // state->exit_crash = 0;
    state->pfds[0].fd = state->fd_ctl_fromserver;
    state->pfds[0].events = POLLIN;

    state->pfds[1].fd = state->fd_data_fromserver;
    state->pfds[1].events = POLLIN;
    state->total_priority = 0;
    init_count_class16();

}
void fork_server_up(FuzzState *state)
{
    printf("wait for fork server\n");
    s32 tmp;
    read(state->fd_ctl_fromserver, &tmp,4);
    printf("fork server is up\n");
}
void fork_server_runonce(FuzzState *state)
{
    s32 tmp;
    write(state->fd_ctl_toserver, &tmp,4);
}

s32 fork_server_getexit(FuzzState *state,u32 *exit_info, u32 *exit_pc)
{
    s32 tmp;
    read(state->fd_ctl_fromserver, &tmp,4);
    read(state->fd_ctl_fromserver, exit_info,4);
    read(state->fd_ctl_fromserver, exit_pc,4);
    return tmp;
}


void run_controlled_process(int argc,char *old_argv[])
{
	pid_t pid;
	char *child_arg[1000];
	int i;
	for(i= 1; i<argc;i++) 
		child_arg[i-1] = old_argv[i];
	child_arg[i-1] = NULL;
	pid = fork();
	if (pid < 0) fatal("fork error\n");
	else if(!pid)
	{
		execv(old_argv[1],child_arg);
	}
}

void dispatch_req(FuzzState *state,queue_entry* entry)
{
  u8 type_recv;
  s32 len;
  u32 mmio_id_recv;


  read(state->fd_data_fromserver, &type_recv, 1);

  if(type_recv == FUZZ_REQ)
  {
    entry->num_mmio++;
    read(state->fd_data_fromserver, &len, 4);
    read(state->fd_data_fromserver, &mmio_id_recv, 4);
    input_stream *stream;
    if(entry->streams->find(mmio_id_recv) == entry->streams->end())
    {
      stream = new_stream(mmio_id_recv, 0);
      entry->streams->insert({mmio_id_recv , stream});
    }
    stream = (*entry->streams)[mmio_id_recv];
    
    if(len > stream->len - stream->used)
    {
      len = -1;
      write(state->fd_data_toserver,&len, 4);
      entry->exit_seed = mmio_id_recv;
    }
    else
    {
      write(state->fd_data_toserver,&len, 4);
      write(state->fd_data_toserver,stream->data + stream->used, len);
      stream->used += len;
    }
  }
  else
  {
    fatal("type error\n");
  }
}

void show_stat(FuzzState *state)
{
  u32 edges = count_non_255_bytes(state->virgin_bits, state->map_size);
  printf("[%d] total exec times:%d edges:%d\n",get_cur_time() / 1000, state->total_exec,edges);
  printf("-----------queue details-----------\n");
  printf("id        depth     bbls      #streams  prio      favorate  none      seed      timeout   crash     exit_pc   exit_seed num_mmio  exec_times\n");
  int count = state->entries->size();
  for(int i = 0; i < count; i++)
  {
    printf("%-10d%-10d%-10d%-10d%-10d%-10x%-10d%-10d%-10d%-10d%-10x%-10x%-10d%-10d\n",
    (*state->entries)[i]->id,
    (*state->entries)[i]->depth,
    (*state->entries)[i]->edges,
    (*state->entries)[i]->streams->size(),
    (*state->entries)[i]->priority,
    (*state->entries)[i]->favorate_stream ? (*state->entries)[i]->favorate_stream->id : 0,
    (*state->entries)[i]->exit_none,(*state->entries)[i]->exit_outofseed,(*state->entries)[i]->exit_timeout,(*state->entries)[i]->exit_crash,
    (*state->entries)[i]->exit_pc,
    (*state->entries)[i]->exit_seed,
    (*state->entries)[i]->num_mmio,
    (*state->entries)[i]->fuzz_times);
  }

  
}
void save_crash(queue_entry* entry)
{
  return;
  static int crash_index = 1;
  char crash_filename[PATH_MAX];
  char crash_folder[PATH_MAX];
  mkdir("./crash/", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  sprintf(crash_folder,"./crash/%d/",crash_index++);
  mkdir(crash_folder, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  
  for (auto it = entry->streams->begin(); it != entry->streams->end(); it++)
  {
    sprintf(crash_filename,"%s%x",crash_folder,it->second->id);
    FILE *f = fopen(crash_filename,"wb");
    if(!f)
    {
      fatal("crash file open error\n");
    }
    fwrite(it->second->data,it->second->used,1,f);
    fclose(f);
  }
}
s32 fuzz_one(FuzzState *state,queue_entry* entry,u32* exit_info, u32* exit_pc)//,u64 * duration)
{
  s32 exit_code;
  //u32 record = 0;
  //u64 start_time = get_cur_time();
  entry->num_mmio = 0;
  memset(state->trace_bits,0,state->map_size);
  fork_server_runonce(state);

  while(1)
  {
    int ready = poll(state->pfds, 2, -1);
    if (ready == -1)
      fatal("poll error\n");
    if(state->pfds[0].revents & POLLIN)
    {
      exit_code = fork_server_getexit(state,exit_info,exit_pc);
      break;
    }
    if(state->pfds[1].revents & POLLIN)
    {
      dispatch_req(state,entry);
    }
  }
  classify_counts((u64*)state->trace_bits,state->map_size);
  state->total_exec ++; 
  entry->fuzz_times++;
  return exit_code;
  //u64 end_time = get_cur_time();
  //*duration = end_time - start_time;
  
  //write(state->fd_ctl_toserver, &record,4);
}
void fuzz_one_post(FuzzState *state,queue_entry* entry, s32 exit_code, u32 exit_info, u32 exit_pc)
{
  int r = has_new_bits_update_virgin(state->virgin_bits, state->trace_bits, state->map_size);
  if(exit_code == EXIT_CRASH)
  {
    //state->exit_crash++;
    entry->exit_crash++;
    save_crash(entry);
    return;
  }
  
  if(exit_code == EXIT_NONE)
  {
    //state->exit_none++;
    entry->exit_none++;

  }
  if(exit_code == EXIT_TIMEOUT)
  {
    //state->exit_timeout++;
    entry->exit_timeout++;

  }
  
  if(exit_code == EXIT_OUTOFSEED)
  {
    //state->exit_outofseed++; 
    entry->exit_outofseed++; 

    
  }
  if(exit_info != 0)
  {
    entry->favorate_stream = (*entry->streams)[exit_info];
  }
  entry->exit_pc = exit_pc;
  if(unlikely(r == 2))
  {
    //record = 1;
    queue_entry* q = copy_queue(state,entry);
    //q->exec_time = end_time - start_time;
    q->edges = count_bytes(state->trace_bits, state->map_size);
    //q->priority = DEFAULT_PRIORITY * q->edges;
    q->priority = DEFAULT_PRIORITY * q->streams->size();
    state->total_priority += q->priority;
    q->exit_pc = exit_pc;
    state->entries->push_back(q);
    show_stat(state);
  }

}
void reset_queue(queue_entry* q)
{
  for (auto it = q->streams->begin(); it != q->streams->end(); it++)
  {
    it->second->used = 0;
  }

}

void free_queue(FuzzState *state,queue_entry* q)
{
  for (auto it = q->streams->begin(); it != q->streams->end(); it++)
  {
    if(it->second->backup_file)
      free(it->second->backup_file);
    if(it->second->data)
    {
      free(it->second->data);
    }
    delete it->second;
  }
  delete q->streams;
  //free(q->compressed_bits);
  
}
void perform_init_run(FuzzState *state)
{
  queue_entry *entry = copy_queue(state,0);

  u32 exit_info,exit_pc;
  s32 exit_code;
  exit_code = fuzz_one(state,entry,&exit_info,&exit_pc);
  fuzz_one_post(state,entry,exit_code,exit_info,exit_pc);
  if(!state->entries->size())
  {
    fatal("init run error\n");
  }
  free_queue(state,entry);
  delete entry;
}
#define FLIP_BIT(_ar, _b) do { \
    u8* _arf = (u8*)(_ar); \
    u32 _bf = (_b); \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf) & 7)); \
  } while (0)
void havoc(FuzzState *state, input_stream* stream)
{
  #define HAVOC_STACK 8
  #define HAVOC_TOKEN 20
  #define ARITH_MAX   35
  u32 use_stacking = 1 + UR(HAVOC_STACK);
  s32 len = stream->len;
  u8 *data = stream->data;
  if(len  <= 8 )
    return;

  for (s32 i = 0; i < use_stacking; i++) 
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
      case 15:
      case 16:
      case 17:
      case 18:
      case 19:
      {
        // if(state->interesting_vals->size() == 0)
        //   break;
        // auto it = state->interesting_vals->begin();
        // std::advance(it, UR(state->interesting_vals->size()));
        // s32* tmp = (s32*)(data + (UR(len - 3) & 0xfffffff4));
        // *tmp = *it;
        s32* tmp1 = (s32*)(data + UR(len - 7));
        s32* tmp2 = (s32*)(data + UR(len - 3));
        *tmp1 = *tmp2 = UR(2);
      } 
      default:
      break;
    }
  }
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
  // not reachable
  return NULL;
}
void fuzz_loop(FuzzState *state)
{ 
    fork_server_up(state);
    perform_init_run(state);
    show_stat(state);
    u8 *org_buf = (u8 *)malloc(MAX_STREAM_LEN);
    vector<struct input_stream *> tmp_streams;
    while(1)
    {
      queue_entry* entry = select_entry(state);
      //for (int i = 0 ; i < 10 ; i++)
      {
        tmp_streams.clear();
        if(entry->favorate_stream)
        {
          if(UR(10) > 6)
          {
            tmp_streams.push_back(entry->favorate_stream);
          }
          else
          {
            for (auto it = entry->streams->begin(); it != entry->streams->end(); it++)
            {
              tmp_streams.push_back(it->second);
            }
          }
        }
        else
        {
          for (auto it = entry->streams->begin(); it != entry->streams->end(); it++)
          {
            tmp_streams.push_back(it->second);
          }
        }

        for(input_stream *stream : tmp_streams)
        {
          u32 exit_info,exit_pc;
          s32 exit_code;
          s32 len = stream->len;  
          memcpy(org_buf, stream->data, len);
          havoc(state, stream);
          exit_code = fuzz_one(state,entry,&exit_info,&exit_pc);
          fuzz_one_post(state,entry,exit_code,exit_info,exit_pc);
          memcpy(stream->data, org_buf, len); 
          
          if((state->total_exec % 10) == 0)
          {
            show_stat(state);
          }
          reset_queue(entry);
        }   
      }
    }
    
}

int main(int argc, char **argv)
{
  FuzzState state;
  fuzzer_init(&state,1 << 16);
  run_controlled_process(argc,argv);
  fuzz_loop(&state);
}

