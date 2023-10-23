#ifndef MODEL_INCLUDED
#define MODEL_INCLUDED
#include <stdint.h>

char* dump_state(uint32_t mmio_id, const char * prefix, char *dir);
void model_irq(int irq);
void model_all_infinite_loop();
#endif