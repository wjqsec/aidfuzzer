#ifndef STREAM_INCLUDED
#define STREAM_INCLUDED
#include "iofuzzer.h"
#include "mutator.h"
#include "fuzzer.h"
input_stream *allocate_new_stream(FuzzState *state,u32 id , u32 len);
input_stream * allocate_enough_space_stream(FuzzState *state,u32 id, s32 len);
void free_stream(FuzzState *state,input_stream *stream);
input_stream *find_queued_stream(FuzzState *state,u32 id);
u32 get_stream_used(FuzzState *state);
void update_stream_ptr(FuzzState *state, u32 used);
input_stream *clone_stream(FuzzState *state,input_stream *stream);
input_stream *extend_stream(FuzzState *state,input_stream *stream,u32 ext_len);
void remove_stream(FuzzState *state,queue_entry* q,input_stream *stream);
void insert_stream(queue_entry* q,input_stream *stream);
void replace_stream(FuzzState *state,queue_entry* q,input_stream *old_tream, input_stream *new_tream);
#endif