#ifndef MUTATOR_INCLUDED
#define MUTATOR_INCLUDED

#include "iofuzzer.h"
input_stream* havoc(FuzzState *state,input_stream* stream);
input_stream* splicing(FuzzState *state,input_stream* stream);
input_stream* increase_stream(FuzzState *state,input_stream* stream);


#endif