#ifndef STREAM_INCLUDED
#define STREAM_INCLUDED
#include "iofuzzer.h"
#include "mutator.h"
#include "fuzzer.h"
input_stream *allocate_new_stream(FuzzState *state,u32 id , u32 len);
input_stream * allocate_enough_space_stream(FuzzState *state,u32 id, s32 len);
void free_stream(FuzzState *state,input_stream *stream);
input_stream *find_queued_stream(FuzzState *state,u32 id);

#endif