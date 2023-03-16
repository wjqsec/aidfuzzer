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

#include <fcntl.h>            /* Definition of AT_* constants */

#include <sys/syscall.h>      /* Definition of SYS_* constants */

#include <sys/time.h>
#include <linux/limits.h>
#include <sys/shm.h>
#include <fcntl.h>              /* Definition of O_* constants */



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
#define EXIT_CRASH 2

struct __attribute__((__packed__)) Data_protocol
{
  #define FUZZ_REQ 0x1
  #define CMP_VAL 0x2
  #define FUZZ_OUTPUT 0x3
  #define ACK 0x4
  u8 type;
  s32 len; // -1 means no more data
  u32 bbl_id;
  u8 data[];
};

#define FORKSRV_CTLFD          198
#define FORKSRV_DATAFD          200

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

u8 count_class_lookup8[256];

u16 count_class_lookup16[65536];
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


struct input_stream
{
    char *backup_file;
    u32 id;
    u8 *data;
    s32 len;
    s32 used;
};

struct queue_entry
{
    u64 exec_time;
    u32 edges;
    s32 depth;
    map<u32,struct input_stream *> *streams;
    vector<u32> *stream_order;
    
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

    vector<struct queue_entry*> *entries;

    set<s32> *interesting_vals;
};




void fatal(const char *msg)
{
    printf("%s",msg);
    exit(0);
}


struct input_stream * new_stream(u32 id, char *file)
{
  struct input_stream *stream = (struct input_stream *)malloc(sizeof(struct input_stream));
  stream->id = id;
  stream->used = 0;

  if(file)
  {
    struct stat st;
    stream->backup_file = strdup(file);
    if (lstat(file, &st) || access(file, R_OK))
    {
      fatal("unable to access backup file\n");
    }
    FILE *fd = fopen("file","rb");
    stream->data = (u8*)malloc(st.st_size);
    stream->len = st.st_size;
    fread(stream->data,st.st_size,1,fd);
    
  }
  else
  {
    stream->backup_file = 0;
    stream->data = (u8*)malloc(0x100);
    stream->len = 0x100;
  }
  return stream;
}
struct queue_entry* copy_queue(struct queue_entry* q)
{
  struct queue_entry *entry = (struct queue_entry *)malloc(sizeof(struct queue_entry));
  entry->depth = q->depth + 1;
  entry->streams = new map<u32,struct input_stream *>();
  for (auto it = q->streams->begin(); it != q->streams->end(); it++)
  {
    struct input_stream *stream = (struct input_stream*)malloc(sizeof(struct input_stream));
    stream->backup_file = 0;
    stream->id = it->second->id;
    stream->len = it->second->len;
    stream->used = 0;
    stream->data = (u8*)malloc(stream->len);
    memcpy(stream->data,it->second->data,stream->len);
    (*entry->streams)[it->first] = stream;
  }
  entry->stream_order = new vector<u32>(*q->stream_order);
  return entry;
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

static u64 get_cur_time(void) {

  struct timeval tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);

}

void fuzzer_init(struct FuzzState *state, u32 map_size) 
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
    state->interesting_vals = new set<s32>();
    state->total_exec = 0;
    state->total_edges = 0;

    state->pfds[0].fd = state->fd_ctl_fromserver;
    state->pfds[0].events = POLLIN;

    state->pfds[1].fd = state->fd_data_fromserver;
    state->pfds[1].events = POLLIN;
    init_count_class16();

}
void fork_server_up(struct FuzzState *state)
{
    s32 tmp;
    read(state->fd_ctl_fromserver, &tmp,4);
    printf("fork server is up\n");
}
inline void fork_server_runonce(struct FuzzState *state)
{
    s32 tmp;
    write(state->fd_data_toserver, &tmp,4);
    printf("run once\n");
}
// void fork_server_getpid(struct FuzzState *state)
// {
//     read(state->fd_fromserver, &state->cur_pid, 4);
// }
inline s32 fork_server_getexit(struct FuzzState *state)
{
    s32 tmp;
    read(state->fd_ctl_fromserver, &tmp,4);
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

void dispatch_req(struct FuzzState *state,struct queue_entry* entry)
{
  u8 type_recv;
  s32 len_recv;
  u32 bbl_id_recv;

  u8 type_send;
  s32 len_send;
  u32 bbl_id_send;

  read(state->fd_data_fromserver, &type_recv, 1);
  read(state->fd_data_fromserver, &len_recv, 4);
  read(state->fd_data_fromserver, &bbl_id_recv, 4);

  bbl_id_send = bbl_id_recv;

  struct input_stream *stream;
  if(entry->streams->find(bbl_id_recv) == entry->streams->end())
  {
    stream = new_stream(bbl_id_recv, 0);
    (*entry->streams)[bbl_id_recv] = stream;
    entry->stream_order->push_back(bbl_id_recv);
  }
  stream = (*entry->streams)[bbl_id_recv];

  if(type_recv == FUZZ_REQ)
  { 
    type_send = FUZZ_OUTPUT;
    if(len_recv > stream->len - stream->used)
    {
      len_send = -1;
      write(state->fd_data_toserver,&type_send, 1);
      write(state->fd_data_toserver,&len_send, 4);
    }
    else
    {
      len_send = len_recv;
      write(state->fd_data_toserver,&type_send, 1);
      write(state->fd_data_toserver,&len_send, 4);
      write(state->fd_data_toserver,&bbl_id_send, 4);
      write(state->fd_data_toserver,stream->data + stream->used, len_send);
      stream->used += len_send;
    }
  }
  else if(type_recv == CMP_VAL)
  {
    type_send = ACK;

  }
  else
  {
    fatal("type error\n");
  }
}
inline void fuzz_one(struct FuzzState *state, struct queue_entry* entry)
{
    
  s32 exit_code;

  u64 start_time = get_cur_time();
  memset(state->trace_bits,0,state->map_size);
  fork_server_runonce(state);

  while(1)
  {
    int ready = poll(state->pfds, 2, -1);
    if (ready == -1)
      fatal("poll error\n");
    if(state->pfds[0].revents & POLLIN)
    {
      exit_code = fork_server_getexit(state);
      break;
    }
    if(state->pfds[1].revents & POLLIN)
    {
      dispatch_req(state,entry);
    }
  }
  u64 end_time = get_cur_time();
  classify_counts((u64*)state->trace_bits,state->map_size);
  int r = has_new_bits_update_virgin(state->virgin_bits, state->trace_bits, state->map_size); 
  if(unlikely(r))
  {
    struct queue_entry* q = copy_queue(entry);
    q->exec_time = end_time - start_time;
    q->edges = count_bytes(state->trace_bits, state->map_size);
    state->entries->push_back(q);
  }
  if(exit_code > 3)
  {
    fatal("crash!\n");
  }
  state->total_exec ++; 
}
void perform_init_run(struct FuzzState *state)
{
  struct queue_entry *entry = (struct queue_entry *)malloc(sizeof(struct queue_entry));
  entry->depth = 0;
  entry->streams = new map<u32,struct input_stream *>();
  entry->stream_order = new vector<u32>();
  fuzz_one(state,entry);
  if(!state->entries->size())
  {
    fatal("init run error\n");
  }
  //memory leak here
}
void mutate(int type, struct input_stream* stream, int offset)
{
  switch(type)
  {

  }
}
void fuzz_loop(struct FuzzState *state)
{ 
    printf("wait for fork server\n");
    fork_server_up(state);
    perform_init_run(state);
    return;
    while (1)
    {
      int count = state->entries->size();
      for(int i = 0; i < count; i ++)
      {
        struct queue_entry* entry = (*state->entries)[i];
        int num_streams = entry->stream_order->size();
        for(int j = 0; j < num_streams; j ++)
        {
          u32 id = (*entry->stream_order)[j];
          struct input_stream *stream = (*entry->streams)[id];
          s32 len = stream->len;
          for(int k = 0; k < len ; k++)
          {
            u8 org[8];
            memcpy(org,stream->data+k,8);
            mutate(1, stream, k);
            fuzz_one(state,entry);
            memcpy(stream->data+k, org, 8);
          }
        }
      }

    }
}

int main(int argc, char **argv)
{
  struct FuzzState state;
  fuzzer_init(&state,1 << 16);
  run_controlled_process(argc,argv);
  fuzz_loop(&state);
}

