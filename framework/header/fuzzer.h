#ifndef FUZZER_INCLUDED

#define FUZZER_INCLUDED

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


#define MAX_STREAM_LEN 0x500000
#define DEFAULT_STREAM_LEN 0x100

#define MAX_BBL_EXEC 150000

#define DEFAULT_ELEMENT_SIZE 4



#define IRQ_STREAM_ID 0xffffffff


#ifndef likely
#define likely(_x)   __builtin_expect(!!(_x), 1)
#endif

#ifndef unlikely
#define unlikely(_x)  __builtin_expect(!!(_x), 0)
#endif


#define SHARE_FUZZDATA_SIZE 1 << 30
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


#define FUZZWARE_PATH "/home/w/hd/iofuzzer/fuzzware"
#define MMIO_MODEL_FILENAME "mmio_model.yml"
#define IRQ_MODEL_FILENAME "irq_model.yml"
//#define ENABLE_IRQ



#define STOPWATCH_TYPE_MMIO 0
#define STOPWATCH_TYPE_MEM 1

#define NUM_WATCHPOINT (1 << 20)
#define NUM_IRQ_PER_WATCHPOINT 20


struct EXIT_INFO
{
    u32 exit_code;
    u32 exit_oufofseed_mmio_id;
    u64 exit_pc;
    u32 num_mmio;
} __attribute__((packed));

struct stream_metadata
{
    u32 stream_id;
    s32 len;
    s32 minimum_len;
    s32 initial_len;
    u32 mode;
    s32 element_size;
    s32 left_shift;
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

#endif


