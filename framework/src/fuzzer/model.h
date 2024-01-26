#ifndef MODEL_INCLUDED
#define MODEL_INCLUDED
#include "iofuzzer.h"


void run_modelling(FuzzState *state,uint32_t id);
void sync_models(FuzzState *state);
void add_default_model(FuzzState *state,u32 id, u32 element_size, u32 mmio_pc, u32 mmio_addr);
void add_irq_model(FuzzState *state);
#endif
