#ifndef MODEL_INCLUDED
#define MODEL_INCLUDED
#include <stdint.h>
#include "xx.h"
char* dump_state(uint32_t id, const char * prefix);
void model_dumped_irq(int irq,hw_addr isr);
void model_all_infinite_loop();
void dump_prcoess_load_model(int irq,hw_addr id ,hw_addr isr, IRQ_N_MODEL **models);
void load_model(char *model_filename, IRQ_N_MODEL **models);
#endif