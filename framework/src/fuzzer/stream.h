#ifndef STREAM_INCLUDED
#define STREAM_INCLUDED
#include "iofuzzer.h"
#include "mutator.h"
#include "fuzzer.h"

input_stream * allocate_enough_space_stream(FuzzState *state,u32 id, s32 len);
void free_stream(FuzzState *state,input_stream *stream);
u32 get_stream_used(FuzzState *state);
void update_stream_ptr(FuzzState *state, u32 used);
void remove_stream(FuzzState *state,queue_entry* q,u32 id);
void insert_stream(FuzzState *state,queue_entry* q,input_stream *stream);
void replace_stream(FuzzState *state,queue_entry* q,u32 id, input_stream *new_tream);
bool stream_shouldnot_mutate(input_stream *stream);
input_stream *resize_stream(FuzzState *state,input_stream *stream,u32 new_len);
#endif