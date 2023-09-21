#include "queue_entry.h"
#include "stream.h"
#include <algorithm>
queue_entry* copy_queue(FuzzState *state,queue_entry* q)
{
    queue_entry *entry = new queue_entry();
    entry->depth = 1;
    entry->priority = DEFAULT_QUEUE_PRIORITY;
    entry->streams = new map<u32,input_stream*>();
    entry->fuzztimes = 0;
    entry->total_stream_len = 0;
    entry->runtime_stream_priority = new map<u32,s32>();
    if(q)
    {
        for(auto it = q->streams->begin(); it != q->streams->end();it++) 
        {
            insert_stream(state,entry,it->second);
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
    delete q->streams;
    delete q->runtime_stream_priority;
    delete q;
}

void insert_queue(FuzzState *state,queue_entry* q)
{
  state->entries->push_back(q);
  state->total_priority += q->priority;
}
void insert_crash(FuzzState *state,crash_info info)
{
    state->crashes->push_back(info);
}
bool find_crash(FuzzState *state, crash_info *info)
{
    for(auto it = state->crashes->begin(); it!= state->crashes->end(); it++)
    {
        if((*it).pc == info->pc &&  (*it).lr == info->lr)
            return true;
    }
    return false;
}

