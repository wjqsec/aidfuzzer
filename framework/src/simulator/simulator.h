#define SHM_ENV_VAR         "__AFL_SHM_ID"
#define SHM_SHARE_STREAM_VAR         "__AFL_STREAM_SHARE"
#define SHM_SHARE_IRQ_VAR         "__AFL_IRQ_SHARE"
#define SHM_SHARE_UNDISCOVER_STREAM_VAR         "__AFL_UNDISCOVER_STREAM_SHARE"
#define SHM_SHARE_FUZZ_QUEUE_VAR "__AFL_QUEUE_SHARE"
//#define DBG
#define CRASH_DBG
//#define TRACE_DBG
#define AFL

#define FORKSRV_CTLFD          198
#define FORKSRV_DATAFD          200

#define EXIT_NONE 0
#define EXIT_TIMEOUT 1
#define EXIT_OUTOFSEED 2
#define EXIT_CRASH 3

#define MODEL_VALUE_SET 0
#define MODEL_BIT_EXTRACT 1
#define MODEL_CONSTANT 2
#define MODEL_PASSTHROUGH 3
#define MODEL_NONE 4

#define NVIC_MAX_VECTORS 512
//#define ENABLE_IRQ
int run_config(struct SIMULATOR_CONFIG *config);
void init(int argc, char **argv);