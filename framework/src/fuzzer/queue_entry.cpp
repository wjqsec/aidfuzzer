#include "queue_entry.h"
#include "stream.h"

queue_entry* copy_queue(FuzzState *state,queue_entry* q)
{
    queue_entry *entry = new queue_entry();
    entry->depth = 1;
    entry->priority = DEFAULT_QUEUE_PRIORITY;
    entry->streams = new map<u32,input_stream*>();
    entry->streams_priority = new map<u32,s32>();
    entry->fuzztimes = 0;
    if(q)
    {
        for(auto it = q->streams->begin(); it != q->streams->end();it++) 
        {
            insert_stream(state,entry,it->second,true);
        }
        entry->depth = q->depth;
    } 
    return entry;
}
void free_queue(FuzzState *state,queue_entry* q)
{
    for(auto it = q->streams->begin(); it != q->streams->end();it++) 
    {
        free_stream(state,it->second);
    }
    delete q->streams_priority;
    delete q->streams;
    delete q;
}

void insert_queue(FuzzState *state,queue_entry* q)
{
  state->entries->push_back(q);
  state->total_priority += q->priority;
}
void insert_crash(FuzzState *state,queue_entry* q)
{
    state->crashes->push_back(q);
}

