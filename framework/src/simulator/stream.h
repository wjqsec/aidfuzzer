#ifndef STREAM_INCLUDED
#define STREAM_INCLUDED
struct SHARED_STREAM
{
    struct stream_metadata *metadata;
    s32 *used;
    bool avaliable;
    bool dumped;
};
struct SHARED_STREAM * streams[NUM_QUEUE_STREAMS];

int num_stream_indexs;
u32 stream_indexs[NUM_QUEUE_STREAMS];
s32 max_stream_size;

struct fuzz_queue *queue;


inline void add_stream(int index_to_shared_queue)
{
    
    u32 index_to_streams;
    struct SHARED_STREAM *stream;
    struct stream_metadata *metadata;
    
    metadata = (struct stream_metadata *)(__afl_share_stream_data + queue->streams[index_to_shared_queue].offset_to_stream_area);

    #ifdef STREAM_MAGIC_CHECK
    if(metadata->magic_number != STREAM_MAGIC)
    {
        printf("stream magic overwritten\n");
        terminate();
    }
    #endif

    index_to_streams = metadata->stream_id % NUM_QUEUE_STREAMS;
    stream = streams[index_to_streams];
    if(stream->avaliable)
    {
        printf("stream index colission id:%x  %x\n",metadata->stream_id,stream->metadata->stream_id);
        terminate();
    }
    stream->avaliable = true;
    stream->used = &queue->streams[index_to_shared_queue].used;
    stream->metadata = metadata;
    stream_indexs[num_stream_indexs] = index_to_streams;
    num_stream_indexs++;

    if(metadata->len > max_stream_size)
            max_stream_size = metadata->len;
    

}
inline void update_stream(int index_to_shared_queue)
{
    u32 index_to_streams;
    struct SHARED_STREAM *stream;
    struct stream_metadata *metadata;
    metadata = (struct stream_metadata *)(__afl_share_stream_data + queue->streams[index_to_shared_queue].offset_to_stream_area);
    index_to_streams = metadata->stream_id % NUM_QUEUE_STREAMS;
    stream = streams[index_to_streams];
    stream->metadata = metadata;

}
inline void clear_streams()
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
        streams[i] = (struct SHARED_STREAM *)malloc(sizeof(struct SHARED_STREAM));
        streams[i]->avaliable = false;
        streams[i]->dumped = false;
    }
}
inline int get_stream_status(struct SHARED_STREAM * stream)
{
    int status = STREAM_STATUS_OK;
    if( stream->metadata->len < stream->metadata->element_size + *stream->used)
    {
        if(stream->metadata->len >= max_stream_size)
        {
            status = STREAM_STATUS_OUTOF;
        }
        else
        {
            status = STREAM_STATUS_NOTENOUGH;
        }
    }
    return status;
}

void get_fuzz_data(struct SHARED_STREAM * stream, uint64_t *out)
{
    
    switch(stream->metadata->mode)
    {
        case MODEL_VALUE_SET:
        {

            uint32_t tmp = 0;
            memcpy(&tmp,stream->metadata->data + *stream->used,stream->metadata->element_size);
            *out = stream->metadata->value_set[tmp % stream->metadata->value_set_size];
            break;
        }
        case MODEL_CONSTANT:
        {
            *out = *(uint32_t*)(stream->metadata->data);
            break;
        }
        
        case MODEL_BIT_EXTRACT:
        {

            memcpy(out,stream->metadata->data + *stream->used,stream->metadata->element_size);
            *out = *out << stream->metadata->left_shift;
            break;
        }
        
        case MODEL_PASSTHROUGH:
        {
            break;
        }
       

        case MODEL_NONE:
        {

            memcpy(out,stream->metadata->data + *stream->used,stream->metadata->element_size);
            break;
        }
        
        default:
        {
            printf("wrong stream type:%d\n",stream->metadata->mode);
            terminate();
            break;
        }
    } 

    num_mmio++;
    nommio_executed_bbls = 0;
    *stream->used += stream->metadata->element_size;
}
#endif