#ifndef STREAM_LOADER_INCLUDED
#define STREAM_LOADER_INCLUDED
#include "stdint.h"
#include "fuzzer.h"
#include "iofuzzer.h"
#include "stream.h"
#include "queue_entry.h"
#include "xx.h"
#include "afl_utl.h"
#include "mis_utl.h"
#include <sys/stat.h>
void save_default_pool(FuzzState *state,char *queue_dir);

void load_default_pool(FuzzState *state,char *queue_dir);
void save_crash_pool(FuzzState *state,char *crash_dir, u32 id);
void load_crash_pool(FuzzState *state,char *filename);


void save_queue(queue_entry *q,char *dir);

void save_crash(queue_entry *q,char *crash_dir);

queue_entry *load_queue(FuzzState *state,char *seedfile);

void save_queues(FuzzState *state,char *queue_dir);


void load_queues(FuzzState *state,char *queue_dir);
void save_freed_streams(FuzzState *state,char *queue_dir);
void load_freed_streams(FuzzState *state,char *queue_dir);
void clean_queues(FuzzState *state,char *queue_dir);
#endif