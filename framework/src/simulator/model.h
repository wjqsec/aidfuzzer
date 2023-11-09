#ifndef MODEL_INCLUDED
#define MODEL_INCLUDED
#include <stdint.h>
#include "xx.h"
char* dump_state(uint32_t mmio_id, const char * prefix, char *dir);
void model_dumped_irq(int irq,hw_addr isr);
void model_all_infinite_loop();
#endif