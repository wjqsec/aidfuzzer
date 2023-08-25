#ifndef QUEUE_ENTRY_INCLUDED
#define QUEUE_ENTRY_INCLUDED
#include "iofuzzer.h"

queue_entry* copy_queue(queue_entry* q);
void free_queue(FuzzState *state,queue_entry* q);
void insert_queue(FuzzState *state,queue_entry* q);
#endif