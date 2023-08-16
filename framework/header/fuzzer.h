#ifndef FUZZER_INCLUDED

#define FUZZER_INCLUDED
#include <sys/time.h>
#define SHM_ENV_VAR         "__AFL_SHM_ID"
#define SHM_SHARE_STREAM_VAR         "__AFL_STREAM_SHARE"
#define SHM_SHARE_IRQ_VAR         "__AFL_IRQ_SHARE"
#define SHM_SHARE_UNDISCOVER_STREAM_VAR         "__AFL_UNDISCOVER_STREAM_SHARE"
#define SHM_SHARE_FUZZ_QUEUE_VAR "__AFL_QUEUE_SHARE"

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t  u64;

typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;

#define EXIT_NONE 0
#define EXIT_TIMEOUT 1
#define EXIT_OUTOFSEED 2
#define EXIT_CRASH 3
#define EXIT_FORKSRV_UP 4
#define EXIT_TERMINATE 5



#define DEFAULT_STREAM_LEN 0x1000

#define MAX_BBL_EXEC 150000

#define DEFAULT_ELEMENT_SIZE 4



#define IRQ_STREAM_ID 0xffffffff


#ifndef likely
#define likely(_x)   __builtin_expect(!!(_x), 1)
#endif

#ifndef unlikely
#define unlikely(_x)  __builtin_expect(!!(_x), 0)
#endif


#define SHARE_FUZZDATA_SIZE 3 << 30
#define FUZZ_COVERAGE_SIZE (1 << 16)

#define MODEL_VALUE_SET 0
#define MODEL_BIT_EXTRACT 1
#define MODEL_CONSTANT 2
#define MODEL_PASSTHROUGH 3
#define MODEL_NONE 4

#define MODE_FUZZ 1
#define MODE_DEBUG 2

#define NVIC_MAX_VECTORS 512

#define MMIO_STATE_PREFIX "state_mmio_"
#define IRQ_STATE_PREFIX "state_irq_"
#define LOOP_STATE_PREFIX "state_loop_"

#define FUZZWARE_PATH "/home/w/hd/iofuzzer/fuzzware"
#define MMIO_MODEL_FILENAME "mmio_model.yml"
#define IRQ_MODEL_FILENAME "irq_model.yml"
#define LOOP_MODEL_FILENAME "loop.yml"
#define STREAM_POOL_FILENAME "pool.bin"
#define FREED_STREAMS_FILENAME "freed_streams"

//#define ENABLE_ROUNDROBIN_IRQ
#define ROUNDROBIN_IRQ_BBLS 0x100


#define STOPWATCH_TYPE_MMIO 0
#define STOPWATCH_TYPE_MEM 1



#define NUM_QUEUE_STREAMS 0x100000


#define CMD_FUZZ 0
#define CMD_TERMINATE 1

struct EXIT_INFO
{
    u32 exit_code;
    u32 exit_oufofseed_mmio_id;
    u64 exit_pc;
    u32 num_mmio;
} __attribute__((packed));

struct stream_metadata
{
#define MAX_VALUE_SET_SIZE 255
    u32 stream_id;
    s32 len;
    s32 initial_len;
    u32 mode;
    s32 element_size;
    s32 left_shift;
    s32 value_set_size;
    u32 value_set[MAX_VALUE_SET_SIZE];
    u8 data[];
} __attribute__((packed));

struct fuzz_queue_stream
{
    u32 offset_to_stream_area;
    u32 used;
} __attribute__((packed));

struct fuzz_queue
{
    u32 num_streams;
    struct fuzz_queue_stream streams[];
}__attribute__((packed));

struct undiscovered_streams
{
    u32 num_streams;
    u32 streams[];
}__attribute__((packed));


static __always_inline uint32_t hash_32(uint32_t number)
{
        return number;
}

static __always_inline uint32_t hash_32_ext (uint32_t number)
{
        uint32_t hash_value = number ^ (number >> 16);
        hash_value = hash_value * 0x85ebca6b;
        hash_value = hash_value ^ (hash_value >> 13);
        hash_value = hash_value * 0xc2b2ae35;
        hash_value = hash_value ^ (hash_value >> 16);
        return hash_value;
}
inline static u64 get_cur_time(void) {

  struct timeval tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);

}
#endif


