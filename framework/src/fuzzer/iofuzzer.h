#define SHM_ENV_VAR         "__AFL_SHM_ID"
#define SHM_SHARE_STREAM_VAR         "__AFL_STREAM_SHARE"
#define SHM_SHARE_IRQ_VAR         "__AFL_IRQ_SHARE"
#define SHM_SHARE_UNDISCOVER_STREAM_VAR         "__AFL_UNDISCOVER_STREAM_SHARE"

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

#define DEFAULT_STREAM_LEN 0x200
#define MAX_STREAM_LEN 0x2000000

#define MAIN_CPU 0

#define likely(_x)   __builtin_expect(!!(_x), 1)
#define unlikely(_x)  __builtin_expect(!!(_x), 0)

#define ENTRY_MUTEX_MEM_SIZE 1024
#define ENTRY_MUTEX_KEY 1234

inline static u64 get_cur_time(void) {

  struct timeval tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);

}