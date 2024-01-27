#include "stream.h"

#include "simulator.h"

#include "fuzzer.h"

SHARED_STREAM * streams[NUM_QUEUE_STREAMS];

int num_stream_indexs;
u32 stream_indexs[NUM_QUEUE_STREAMS];


struct fuzz_queue *queue;


void add_stream(int index_to_shared_queue)
{
    
    u32 index_to_streams;
    SHARED_STREAM *stream;
    struct stream_metadata *metadata;
    
    metadata = (struct stream_metadata *)(__afl_share_stream_data + queue->streams[index_to_shared_queue].offset_to_stream_area);

    
    #ifdef STREAM_MAGIC_CHECK
    if(metadata->magic_number != STREAM_MAGIC)
    {
        printf("stream magic overwritten\n");
        terminate_simulation();
    }
    #endif

    index_to_streams = metadata->stream_id % NUM_QUEUE_STREAMS;
    stream = streams[index_to_streams];
    if(stream->avaliable)
    {
        printf("stream index colission id:%x  %x  index: %d  offset:%x\n",metadata->stream_id,stream->id,index_to_shared_queue,queue->streams[index_to_shared_queue].offset_to_stream_area);
        terminate_simulation();
    }
    stream->avaliable = true;
    stream->id = metadata->stream_id;
    stream->used = &queue->streams[index_to_shared_queue].used;
    stream->metadata = metadata;
    stream_indexs[num_stream_indexs] = index_to_streams;
    num_stream_indexs++;
    

}
void update_stream(int index_to_shared_queue)
{
    u32 index_to_streams;
    SHARED_STREAM *stream;
    struct stream_metadata *metadata;
    metadata = (struct stream_metadata *)(__afl_share_stream_data + queue->streams[index_to_shared_queue].offset_to_stream_area);
    index_to_streams = metadata->stream_id % NUM_QUEUE_STREAMS;
    stream = streams[index_to_streams];
    stream->metadata = metadata;

}
void clear_streams()
{
    u32 i;
    for(i = 0 ;i < num_stream_indexs; i++)
    {
        streams[stream_indexs[i]]->avaliable = false;
    }
    num_stream_indexs = 0;
}
void collect_streams()
{
    u32 i;

    clear_streams();
    for(i = 0; i < queue->num_streams ; i++)
    {
        add_stream(i);
        
    }   
}
void init_streams()
{
    for(int i = 0; i < NUM_QUEUE_STREAMS ;i ++)
    {
        streams[i] = (SHARED_STREAM *)malloc(sizeof(SHARED_STREAM));
        streams[i]->id = 0;
        streams[i]->avaliable = false;
        streams[i]->dumped = false;
    }
}
int get_stream_status(SHARED_STREAM * stream)
{
    int status = STREAM_STATUS_OK;
    if (stream->metadata->mode == MODEL_CONSTANT ||stream->metadata->mode ==  MODEL_PASSTHROUGH)
        return status;
    if( stream->metadata->len < stream->metadata->element_size + *stream->used)
    {
        status = STREAM_STATUS_OUTOF;
    }
    return status;
}
SHARED_STREAM *get_stream(uint32_t id)
{
    return streams[id % NUM_QUEUE_STREAMS];
}
void get_fuzz_data(SHARED_STREAM * stream, uint64_t *out)
{
    
    switch(stream->metadata->mode)
    {
        case MODEL_VALUE_SET:
        {

            uint32_t tmp = 0;
            memcpy(&tmp,stream->metadata->data + *stream->used,stream->metadata->element_size);
            *out = stream->metadata->value_set[tmp % stream->metadata->value_set_size];
            *stream->used += stream->metadata->element_size;
            break;
        }
        case MODEL_CONSTANT:
        {
            *out = *(uint32_t*)(stream->metadata->data);
            break;
        }
        
        case MODEL_BIT_EXTRACT:
        case MODEL_NONE:
        {

            memcpy(out,stream->metadata->data + *stream->used,stream->metadata->element_size);
            *out = *out << stream->metadata->left_shift;
            *stream->used += stream->metadata->element_size;
            break;
        }
        
        case MODEL_PASSTHROUGH:
        {
            break;
        }
        default:
        {
            printf("wrong stream type:%d\n",stream->metadata->mode);
            terminate_simulation();
            break;
        }
    } 
    mmio_times++;
    nommio_executed_bbls = 0;
    
}
void set_queue_addr(void *ptr)
{
    queue = (struct fuzz_queue *)ptr;
}