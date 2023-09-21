#include <assert.h>
#include "stream.h"
#include "afl_utl.h"
#include "mis_utl.h"
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
  stream->ref_count--;
  if(stream->ref_count > 0)
    return;
  stream->ref_count = 0;
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
  freed_streams->erase(need_remove);
  ret->ptr->len = len;
  ret->priority = DEFAULT_STREAM_PRIORITY;
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
      if(stream->ptr->mode == MODEL_NONE)
      {
        stream->ptr->left_shift = 0;
        stream->ptr->element_size = it->second->access_size;
      }
    }
  }

  stream->ptr->initial_len = stream->ptr->len;
  update_stream_ptr(state, sizeof(stream_metadata) + stream->ptr->len);
  return stream;
}

input_stream * allocate_enough_space_stream(FuzzState *state,u32 id, s32 len)
{
  input_stream * ret;
  ret = allocate_freed_enough_space_stream(state,id,len);
  if(!ret)
    ret = allocate_new_stream(state,id,len);
  return ret;
}

input_stream *extend_stream(FuzzState *state,input_stream *stream,u32 ext_len)
{
  input_stream *ret = allocate_enough_space_stream(state,stream->ptr->stream_id,stream->ptr->len + ext_len);
  memcpy(ret->ptr->data,stream->ptr->data,stream->ptr->len);
  return ret;
}

input_stream *clone_stream(FuzzState *state,input_stream *stream)
{
  return extend_stream(state,stream,0);
}
input_stream *decrease_stream(FuzzState *state,input_stream *stream,u32 new_len)
{
  if(new_len >= stream->ptr->len)
  {
    fatal("decrease stream should at lease remove some elements\n");
  }
  input_stream *ret = allocate_enough_space_stream(state,stream->ptr->stream_id,new_len);
  memcpy(ret->ptr->data,stream->ptr->data,new_len);
  return ret;
}

void insert_stream(FuzzState *state,queue_entry* q,input_stream *stream)
{

  stream->ref_count++;
  (*q->streams)[stream->ptr->stream_id] = stream;
  (*q->runtime_stream_priority)[stream->ptr->stream_id] = 1;

}
void remove_stream(FuzzState *state,queue_entry* q,u32 id)
{
  free_stream(state,(*q->streams)[id]);
  q->streams->erase(id);
  q->runtime_stream_priority->erase(id);
  
}
void replace_stream(FuzzState *state,queue_entry* q,u32 id, input_stream *new_tream)
{

  remove_stream(state,q,id);
  insert_stream(state,q,new_tream);
}
bool stream_shouldnot_mutate(input_stream *stream)
{
  return (stream->ptr->mode == MODEL_CONSTANT || stream->ptr->mode == MODEL_PASSTHROUGH  || stream->ptr->len == 0);
}

