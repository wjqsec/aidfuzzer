#ifndef STREAM_INCLUDED
#define STREAM_INCLUDED

#include <stdbool.h>
#include <stdint.h>
#include "fuzzer.h"
typedef struct _SHARED_STREAM
{
    struct stream_metadata *metadata;
    s32 *used;
    bool avaliable;
    bool dumped;
}SHARED_STREAM;


void add_stream(int index_to_shared_queue);
void update_stream(int index_to_shared_queue);
void clear_streams();
void collect_streams();
SHARED_STREAM *get_stream(uint32_t id);
void set_queue_addr(void *ptr);
void init_streams();
int get_stream_status(SHARED_STREAM * stream);
void get_fuzz_data(SHARED_STREAM * stream, uint64_t *out);

#endif