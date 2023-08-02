#include <assert.h>
#include "stream.h"
#include "afl_utl.h"

u32 get_stream_used(FuzzState *state)
{
  return state->shared_stream_used;
}
void update_stream_ptr(FuzzState *state, u32 used)
{
  state->shared_stream_used += used;
}

input_stream *find_queued_stream(FuzzState *state,u32 id)
{
  vector<input_stream *> *queue_streams;
  if(state->all_queued_streams->count(id) == 0)
  {
    return nullptr;
  }
  queue_streams = (*state->all_queued_streams)[id];
  if(queue_streams->size() == 0)
    return nullptr;
  
  return (*queue_streams)[0];
}

void free_stream(FuzzState *state,input_stream *stream)
{
  u32 id = stream->ptr->stream_id;
  vector<input_stream *> *freed_streams;
  if(state->freed_streams->count(id) == 0)
  {
    (*state->freed_streams)[id] = new vector<input_stream *>();
  }
  freed_streams = (*state->freed_streams)[id];
  freed_streams->push_back(stream);

}

input_stream * allocate_freed_enough_space_stream(FuzzState *state,u32 id, s32 len)
{
  input_stream * ret = nullptr;
  vector<input_stream *>::iterator need_remove;
  vector<input_stream *> *freed_streams;
  if(state->freed_streams->count(id) == 0)
    return ret;
  freed_streams = (*state->freed_streams)[id];

  for(auto it = freed_streams->begin(); it != freed_streams->end();it++)
  {
    if((*it)->ptr->initial_len >= len)
    {
      ret = *it;
      need_remove = it;
      break;
    }
      
  }
  if(!ret)
    return ret;
  ret->ptr->len = len;
  freed_streams->erase(need_remove);
  return ret;
}



input_stream *allocate_new_stream(FuzzState *state,u32 id , u32 len)
{
  u32 i;
  input_stream *stream = new input_stream();
  if(!stream)
    fatal("allocate new_stream memory error\n");

  stream->priority = DEFAULT_STREAM_PRIORITY;
  stream->offset_to_stream_area = get_stream_used(state);
  stream->ptr = (stream_metadata*)(state->shared_stream_data + stream->offset_to_stream_area);
  
  
  stream->ptr->stream_id = id;
  stream->ptr->len = len;
  stream->ptr->mode = MODEL_NONE;
  stream->ptr->element_size = DEFAULT_ELEMENT_SIZE;
  stream->ptr->left_shift = 0;
    
    
  for(auto it = state->models->begin() ; it != state->models->end() ; it++)
  {
    if(it->first == stream->ptr->stream_id)
    {
      stream->ptr->mode = it->second->mode;
      if(stream->ptr->mode == MODEL_VALUE_SET)
      {
        assert(it->second->values->size() && it->second->values->size() < MAX_VALUE_SET_SIZE);
        stream->ptr->element_size = 1;
        i = 0;
        stream->ptr->value_set_size = it->second->values->size();
        for(auto it2 = it->second->values->begin() ; it2 != it->second->values->end() ; it2++)
        {
          stream->ptr->value_set[i++] = *it2;
        }
      }
      if(stream->ptr->mode == MODEL_CONSTANT)
      {
        stream->ptr->len = 4;
        *(u32*)stream->ptr->data = it->second->constant_val;
      }
      if(stream->ptr->mode == MODEL_PASSTHROUGH)
      {
        stream->ptr->len = 4;
      }
      if(stream->ptr->mode == MODEL_BIT_EXTRACT)
      {
        stream->ptr->left_shift = it->second->left_shift;
        stream->ptr->element_size = it->second->size;
      }
    }
  }
    
  stream->ptr->initial_len = stream->ptr->len;
  update_stream_ptr(state, sizeof(stream_metadata) + stream->ptr->len);
  return stream;
}

input_stream * allocate_enough_space_stream(FuzzState *state,u32 id, s32 len)
{
  input_stream * ret = allocate_freed_enough_space_stream(state,id,len);
  if(!ret)
    ret = allocate_new_stream(state,id,len);
  return ret;
}

