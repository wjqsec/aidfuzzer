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
void zero_stream_ptr(FuzzState *state)
{
  state->shared_stream_used = 0;
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
  return ret;
}

void rearrange_pool(FuzzState *state)
{
  void *tmp_buf;
  map<input_stream *,void*> all_streams;
  for(auto it = state->entries->begin(); it != state->entries->end(); it++)
  {
    for(auto s = (*it)->streams->begin(); s != (*it)->streams->begin(); s++)
    {
      if(all_streams.find(s->second) != all_streams.end())
        continue;
      int len = sizeof(stream_metadata) + s->second->ptr->len;
      tmp_buf = (uint8_t *)malloc(len);
      memcpy(tmp_buf,s->second->ptr,len);
      all_streams[s->second] = tmp_buf;
    }
  }
  zero_stream_ptr(state);
  for(auto it = all_streams.begin(); it != all_streams.end(); it++)
  {
    int len = sizeof(stream_metadata) + it->first->ptr->len;
    it->first->offset_to_stream_area = get_stream_used(state);
    it->first->ptr = (stream_metadata*)(state->shared_stream_data + it->first->offset_to_stream_area);
    
    memcpy(it->first->ptr,it->second,len);
    it->first->ptr->initial_len = len;
    free(it->second);
    update_stream_ptr(state, len);
  }
  state->freed_streams->clear();
}

input_stream *allocate_new_stream(FuzzState *state,u32 id , u32 len)
{
  u32 i;
  input_stream *stream = new input_stream();

  stream->offset_to_stream_area = get_stream_used(state);
  stream->ref_count = 0;
  stream->ptr = (stream_metadata*)(state->shared_stream_data + stream->offset_to_stream_area);
  
  #ifdef STREAM_MAGIC_CHECK
  stream->ptr->magic_number = STREAM_MAGIC;
  #endif
  stream->ptr->stream_id = id;
  stream->ptr->len = len;
    
  
  if(state->models->find(id) != state->models->end())
  {
    input_model *model = (*state->models)[stream->ptr->stream_id];
    stream->ptr->mode = model->mode;
    if(stream->ptr->mode == MODEL_VALUE_SET)
    {
      assert(model->values->size() && model->values->size() < MAX_VALUE_SET_SIZE);
      stream->ptr->element_size = 1;
      i = 0;
      stream->ptr->value_set_size = model->values->size();
      for(auto it2 = model->values->begin() ; it2 != model->values->end() ; it2++)
      {
        stream->ptr->value_set[i++] = *it2;
      }
    }
    if(stream->ptr->mode == MODEL_CONSTANT)
    {
      stream->ptr->element_size = 4;
      stream->ptr->len = stream->ptr->element_size;
      *(u32*)stream->ptr->data = model->constant_val;
    }
    if(stream->ptr->mode == MODEL_PASSTHROUGH)
    {
      stream->ptr->element_size = 4;
      stream->ptr->len = stream->ptr->element_size;
    }
    if(stream->ptr->mode == MODEL_BIT_EXTRACT)
    {
      stream->ptr->left_shift = model->left_shift;
      stream->ptr->element_size = model->size;
    }
    if(stream->ptr->mode == MODEL_NONE)
    {
      stream->ptr->left_shift = 0;
      stream->ptr->element_size = model->access_size;
    }

  }
  else
  {
    printf("stream model not found\n");
    exit(0);
  }

  stream->ptr->initial_len = stream->ptr->len;
  update_stream_ptr(state, sizeof(stream_metadata) + stream->ptr->len);
  return stream;
}

input_stream * allocate_enough_space_stream(FuzzState *state,u32 id, s32 len)
{
  if(state->models->find(id) != state->models->end())
  {
    input_model *model = (*state->models)[id];
    if(model->mode == MODEL_CONSTANT || model->mode == MODEL_PASSTHROUGH)
    {
      len = 4;
    }
  }
  input_stream * ret;
  ret = allocate_freed_enough_space_stream(state,id,len);
  if(!ret)
    ret = allocate_new_stream(state,id,len);
  return ret;
}

input_stream *resize_stream(FuzzState *state,input_stream *stream,u32 new_len)
{
  u32 copy_len = stream->ptr->len < new_len ? stream->ptr->len : new_len;
  input_stream *ret = allocate_enough_space_stream(state,stream->ptr->stream_id,new_len);
  memcpy(ret->ptr->data,stream->ptr->data,copy_len);
  return ret;
}

void insert_stream(FuzzState *state,queue_entry* q,input_stream *stream)
{
  stream->ref_count++;
  (*q->streams)[stream->ptr->stream_id] = stream;
 
}
void remove_stream(FuzzState *state,queue_entry* q,u32 id)
{
  free_stream(state,(*q->streams)[id]);
  q->streams->erase(id);
}
void replace_stream(FuzzState *state,queue_entry* q,u32 id, input_stream *new_tream)
{
  remove_stream(state,q,id);
  insert_stream(state,q,new_tream);
}
bool stream_shouldnot_mutate(input_stream *stream)
{
  return (stream->ptr->mode == MODEL_CONSTANT || stream->ptr->mode == MODEL_PASSTHROUGH);
}

