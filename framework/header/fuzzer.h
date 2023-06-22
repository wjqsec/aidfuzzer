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

#define FORKSRV_CTLFD          198
#define FORKSRV_DATAFD          200

#define FUZZ_REQ 0x1
#define CMP_VAL 0x2
#define FUZZ_OUTPUT 0x3
#define ACK 0x4


#define MAX_STREAM_LEN 0x500000
#define DEFAULT_STREAM_LEN 0x5000

#define DEFAULT_ELEMENT_SIZE 4
#define DEFAULT_IRQ_ELEMENT_SIZE 1

#define IRQ_STREAM_ID 0xffffffff

#define MAIN_CPU 0

#ifndef likely
#define likely(_x)   __builtin_expect(!!(_x), 1)
#endif

#ifndef unlikely
#define unlikely(_x)  __builtin_expect(!!(_x), 0)
#endif

#define ENTRY_MUTEX_MEM_SIZE 1024
#define ENTRY_MUTEX_KEY 1234

#define SHARE_FUZZDATA_SIZE 500 << 20
#define FUZZ_COVERAGE_SIZE 1 << 20

#define MODEL_VALUE_SET 0
#define MODEL_BIT_EXTRACT 1
#define MODEL_CONSTANT 2
#define MODEL_PASSTHROUGH 3
#define MODEL_NONE 4

#define NVIC_MAX_VECTORS 512

#define NUM_BBL_CHECK_INTERRUPT 0x3f

//#define ENABLE_IRQ

static __always_inline uint32_t hash_32(uint32_t number)
{
        return number;
        // uint32_t hash_value = number ^ (number >> 16);
        // hash_value = hash_value * 0x85ebca6b;
        // hash_value = hash_value ^ (hash_value >> 13);
        // hash_value = hash_value * 0xc2b2ae35;
        // hash_value = hash_value ^ (hash_value >> 16);
        // return hash_value;
}

