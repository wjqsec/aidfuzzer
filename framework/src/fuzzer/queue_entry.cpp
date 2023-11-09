#include "queue_entry.h"
#include "stream.h"
#include <algorithm>
queue_entry* new_queue(FuzzState *state)
{
    queue_entry *entry = new queue_entry();
    entry->streams = new map<u32,input_stream*>();
    entry->stream_info = 0;
    entry->fuzztimes = 0;
    
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
    if (q->stream_info)
        delete q->stream_info;
    delete q;
}

void insert_queue(FuzzState *state,queue_entry* q)
{
    state->entries->push_back(q);
    state->total_queue_priority += q->priority;
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

