#ifndef MODEL_INCLUDED
#define MODEL_INCLUDED
#include "iofuzzer.h"


void run_modelling(FuzzState *state,Simulator *simulator);
void sync_models(FuzzState *state,Simulator *simulator);
void add_default_model(FuzzState *state,u32 id, u32 element_size);
#endif
