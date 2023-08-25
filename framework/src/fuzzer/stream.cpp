#include <assert.h>
#include "stream.h"
#include "afl_utl.h"
#include <string.h>
u32 get_stream_used(FuzzState *state)
{
  return state->shared_stream_used;
}
void update_stream_ptr(FuzzState *state, u32 used)
{
  state->shared_stream_used += used;
}

void free_stream(FuzzState *state,input_stream *stream)
{
  if(stream->ref_count > 0 )
    stream->ref_count--;
  if(stream->ref_count > 0)
    return;
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

  stream->priority = DEFAULT_STREAM_PRIORITY;
  stream->offset_to_stream_area = get_stream_used(state);
  stream->ptr = (stream_metadata*)(state->shared_stream_data + stream->offset_to_stream_area);
  
  #ifdef STREAM_MAGIC_CHECK
  stream->ptr->magic_number = STREAM_MAGIC;
  #endif
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
        stream->ptr->len = DEFAULT_PASSTHROUGH_CONSTANT_LEN;
        *(u32*)stream->ptr->data = it->second->constant_val;
      }
      if(stream->ptr->mode == MODEL_PASSTHROUGH)
      {
        stream->ptr->len = DEFAULT_PASSTHROUGH_CONSTANT_LEN;
      }
      if(stream->ptr->mode == MODEL_BIT_EXTRACT)
      {
        stream->ptr->left_shift = it->second->left_shift;
        stream->ptr->element_size = it->second->size;
      }
    }
  }
  stream->mutation_len =  stream->ptr->len;
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

input_stream *extend_stream(FuzzState *state,input_stream *stream,u32 ext_len)
{
  input_stream *ret = allocate_enough_space_stream(state,stream->ptr->stream_id,stream->ptr->len + ext_len);
  ret->ptr->len = stream->ptr->len + ext_len;
  memcpy(ret->ptr->data,stream->ptr->data,stream->ptr->len);
  ret->priority = stream->priority;
  ret->mutation_len = stream->mutation_len;
  return ret;
}

input_stream *clone_stream(FuzzState *state,input_stream *stream)
{
  return extend_stream(state,stream,0);
}

void replace_stream(FuzzState *state,queue_entry* q,input_stream *old_tream, input_stream *new_tream)
{
  free_stream(state,old_tream);
  new_tream->ref_count++;
  (*q->streams)[old_tream->ptr->stream_id] = new_tream;
}
void insert_stream(queue_entry* q,input_stream *stream)
{
  stream->ref_count++;
  (*q->streams)[stream->ptr->stream_id] = stream;
}
void remove_stream(FuzzState *state,queue_entry* q,input_stream *stream)
{
  free_stream(state,stream);
  q->streams->erase(stream->ptr->stream_id);
}

