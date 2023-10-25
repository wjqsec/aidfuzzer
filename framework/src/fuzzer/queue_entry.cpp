#include "queue_entry.h"
#include "stream.h"
#include <algorithm>
queue_entry* new_queue(FuzzState *state)
{
    queue_entry *entry = new queue_entry();
    entry->streams = new map<u32,input_stream*>();
    entry->stream_priority = new map<u32,u64>;
    entry->fuzztimes = 0;
    entry->total_stream_len = 0;
    entry->total_stream_priority = 0;
    
    return entry;
}
void copy_queue_streams(FuzzState *state,queue_entry* from,queue_entry* to)
{
    for(auto it = from->streams->begin(); it != from->streams->end();it++) 
    {
        insert_stream(state,to,it->second);
    }
}
void free_queue(FuzzState *state,queue_entry* q)
{
    for(auto it = q->streams->begin(); it != q->streams->end();it++) 
    {
        free_stream(state,it->second);
    }
    delete q->streams;
    delete q->stream_priority;
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

