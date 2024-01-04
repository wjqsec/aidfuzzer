#ifndef FUZZER_INCLUDED
#define FUZZER_INCLUDED


#include <sys/time.h>
#include <stdint.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t  u64;

typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;

#ifndef likely
#define likely(_x)   __builtin_expect(!!(_x), 1)
#endif

#ifndef unlikely
#define unlikely(_x)  __builtin_expect(!!(_x), 0)
#endif


#define SHM_ENV_VAR         "__AFL_SHM_ID"
#define SHM_SHARE_STREAM_VAR         "__AFL_STREAM_SHARE"
#define SHM_SHARE_FUZZ_QUEUE_VAR "__AFL_QUEUE_SHARE"




#define DEFAULT_PASSTHROUGH_CONSTANT_LEN 0x10000
#define MAX_BBL_EXEC 150000



#define ROUNDROBIN_IRQ_BBLS 1000

#define NUM_QUEUE_STREAMS 0x1000000
#define SHARE_FUZZDATA_SIZE 1 << 30
#define SHARE_FUZZQUEUE_SIZE 10 << 20

#define ONEBYTE_COVERAGE
// #define TWOBYTES_COVERAGE

#if defined(ONEBYTE_COVERAGE) && defined(TWOBYTES_COVERAGE)
#error "Only one size is supported"
#endif 



#define FUZZ_COVERAGE_NUM (1 << 16)

#ifdef ONEBYTE_COVERAGE
#define FUZZ_COVERAGE_ELEMENT_TYPE uint8_t
#endif

#ifdef TWOBYTES_COVERAGE
#define FUZZ_COVERAGE_ELEMENT_TYPE uint16_t
#endif


#define FUZZ_COVERAGE_ELEMENT_SIZE sizeof(FUZZ_COVERAGE_ELEMENT_TYPE)
#define FUZZ_COVERAGE_SIZE (FUZZ_COVERAGE_NUM * FUZZ_COVERAGE_ELEMENT_SIZE)


#define MMIO_STATE_PREFIX "state_mmio_"
#define IRQ_STATE_PREFIX "state_irq_"
#define LOOP_STATE_PREFIX "state_loop_"

#define FUZZWARE_PATH "/home/w/hd/iofuzzer/fuzzware"
#define MMIO_MODEL_FILENAME "mmio_model.yml"
#define IRQ_MODEL_FILENAME "irq_model.yml"
#define LOOP_MODEL_FILENAME "loop.yml"
#define STREAM_POOL_FILENAME "pool.bin"
#define FREED_STREAMS_FILENAME "freed_streams"



#define MODE_FUZZ 1
#define MODE_RUN 2
#define MODE_DEBUG 3

// #define STREAM_MAGIC_CHECK

typedef enum _EXIT_REASON 
{
    EXIT_FUZZ_STREAM_NOTFOUND = 0,
    EXIT_FUZZ_OUTOF_STREAM,
    EXIT_FUZZ_TIMEOUT,
    EXIT_FUZZ_CRASH,
    EXIT_FUZZ_BKP,
    EXIT_FUZZ_EXCP_DEBUG,
    EXIT_FUZZ_EXCP_INTERRUPT,
    EXIT_FUZZ_EXCP_YIELD,
    EXIT_FUZZ_EXCP_ATOMIC,
    EXIT_DBG_STREAM_NOTFOUND,
    EXIT_CTL_FORKSRV_UP,
    EXIT_CTL_TERMINATE,
    EXIT_MAX,
}EXIT_REASON;


static const char* fuzzer_exit_names[] = 
{
    "EXIT_FUZZ_STREAM_NOTFOUND",
    "EXIT_FUZZ_OUTOF_STREAM",
    "EXIT_FUZZ_TIMEOUT",
    "EXIT_FUZZ_CRASH",
    "EXIT_FUZZ_BKP",
    "EXIT_FUZZ_EXCP_DEBUG",
    "EXIT_FUZZ_EXCP_INTERRUPT",
    "EXIT_FUZZ_EXCP_YIELD",
    "EXIT_FUZZ_EXCP_ATOMIC",
    "EXIT_DBG_STREAM_NOTFOUND",
    "EXIT_CTL_FORKSRV_UP",
    "EXIT_CTL_TERMINATE",
    "EXIT_MAX",
};

static const char* get_fuzz_exit_name(int exit_code)
{
    return fuzzer_exit_names[exit_code];
}


typedef enum _STREAM_STATUS
{
    STREAM_STATUS_OK = 0,
    STREAM_STATUS_OUTOF,
}STREAM_STATUS;


typedef enum _STREAM_MODEL
{
    MODEL_NONE,
    MODEL_VALUE_SET,
    MODEL_BIT_EXTRACT,
    MODEL_CONSTANT,
    MODEL_PASSTHROUGH
}STREAM_MODEL;


typedef enum 
{
    CMD_FUZZ = 1,
    CMD_CONTINUE_UPDATE_STREAM,
    CMD_CONTINUE_ADD_STREAM,
    CMD_TERMINATE,
}CMD_CODE;


typedef struct _CMD_INFO
{
    u32 cmd;
    u32 added_stream_index;
    u32 updated_stream_index;
} __attribute__((packed)) CMD_INFO;


typedef struct _EXIT_INFO
{
    u32 exit_code;
    u32 exit_pc;
    u32 exit_lr;
    u32 unique_bbls;
    struct 
    {
        u32 exit_stream_id;
        u32 exit_mmio_addr;
        u32 mmio_len;
    } stream_info;
} __attribute__((packed)) EXIT_INFO;





struct stream_metadata
{
#define MAX_VALUE_SET_SIZE 255
#ifdef STREAM_MAGIC_CHECK
#define STREAM_MAGIC 0xdeadbeef
    u32 magic_number;
#endif
    u32 stream_id;
    s32 len;
    s32 initial_len;
    u32 mode;
    s32 element_size;
    s32 left_shift;
    s32 value_set_size;
    u32 value_set[MAX_VALUE_SET_SIZE];
    u8 data[];
}__attribute__((packed));


struct fuzz_queue_stream
{
    u32 offset_to_stream_area;
    s32 used;
} __attribute__((packed));



struct fuzz_queue
{
    u32 num_streams;
    struct fuzz_queue_stream streams[];
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


