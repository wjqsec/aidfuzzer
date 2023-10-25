#ifndef QUEUE_ENTRY_INCLUDED
#define QUEUE_ENTRY_INCLUDED
#include "iofuzzer.h"

void copy_queue_streams(FuzzState *state,queue_entry* from,queue_entry* to);
queue_entry* new_queue(FuzzState *state);

void free_queue(FuzzState *state,queue_entry* q);
void insert_queue(FuzzState *state,queue_entry* q);
void insert_crash(FuzzState *state,crash_info info);
bool find_crash(FuzzState *state, crash_info *info);
#endif