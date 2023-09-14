#include <stdio.h>
#include "simulator.h"
#include "iofuzzer.h"
#include "afl_utl.h"
#include <string.h>
#include <unistd.h>
#include "mis_utl.h"


void simulator_task(Simulator *simulator,queue_entry* fuzz_entry,queue_entry* base_entry, u32 fuzz_stream_id)
{
  simulator->fuzz_entry = fuzz_entry;
  simulator->base_entry = base_entry;
  simulator->fuzz_stream_id = fuzz_stream_id;
}
void copy_fuzz_data(Simulator *simulator)
{
  int i = 0;
  simulator->id_queue_idx_mapping->clear();
  map<u32,input_stream *> *streams;
  fuzz_queue *queue = (fuzz_queue *)simulator->shared_fuzz_queue_data;
  streams = simulator->fuzz_entry->streams;
  queue->num_streams = streams->size();


  for(auto it = streams->begin(); it != streams->end(); it++)
  {
    queue->streams[i].offset_to_stream_area = it->second->offset_to_stream_area;
    queue->streams[i].used = 0;
    (*simulator->id_queue_idx_mapping)[it->first] = i;
    i++;
  }

}
void fuzz_start(Simulator *simulator)
{
  CMD_INFO cmd_info;
  cmd_info.cmd = CMD_FUZZ;
  memset(simulator->trace_bits,0,simulator->map_size);
  copy_fuzz_data(simulator);
  write(simulator->fd_ctl_to_simulator, &cmd_info,sizeof(CMD_INFO));
  simulator->status = STATUS_RUNNING;


}
void fuzz_continue_stream_notfound(Simulator *simulator,input_stream *new_stream)
{
  CMD_INFO cmd_info;
  cmd_info.cmd = CMD_CONTINUE_ADD_STREAM;
  fuzz_queue *queue = (fuzz_queue *)simulator->shared_fuzz_queue_data;

  cmd_info.added_stream_index = queue->num_streams;
  queue->streams[queue->num_streams].offset_to_stream_area = new_stream->offset_to_stream_area;

  queue->streams[queue->num_streams].used = 0;

  (*simulator->id_queue_idx_mapping)[new_stream->ptr->stream_id] = queue->num_streams;

  queue->num_streams++;

  
  write(simulator->fd_ctl_to_simulator, &cmd_info,sizeof(CMD_INFO));
  simulator->status = STATUS_RUNNING;
}
void fuzz_continue_stream_outof(Simulator *simulator,input_stream *new_stream)
{
  input_stream *tmp;
  CMD_INFO cmd_info;
  int idx;
  cmd_info.cmd = CMD_CONTINUE_UPDATE_STREAM;
  fuzz_queue *queue = (fuzz_queue *)simulator->shared_fuzz_queue_data;
  idx = (*simulator->id_queue_idx_mapping)[new_stream->ptr->stream_id];
  queue->streams[idx].offset_to_stream_area = new_stream->offset_to_stream_area;
  cmd_info.updated_stream_index = idx;
  write(simulator->fd_ctl_to_simulator, &cmd_info,sizeof(CMD_INFO));
  simulator->status = STATUS_RUNNING;

}
void fuzz_exit(Simulator *simulator,EXIT_INFO *exit_info)
{
  read(simulator->fd_ctl_from_simulator, exit_info,sizeof(EXIT_INFO));
  
  simulator->status = STATUS_FREE;
  simulator->state->total_exec++;
  simulator->state->exit_reason[exit_info->exit_code]++;
  simulator->status = STATUS_FREE;


}
void fuzz_exit_timeout(Simulator *simulator,EXIT_INFO *exit_info, u32 seconds, bool *timeout)
{
  struct pollfd pfd[1];
  int ret;
  pfd[0].fd = simulator->fd_ctl_from_simulator;
  pfd[0].events = POLLIN;
  ret = poll(pfd, 1, seconds * 1000);
  if(ret == 0)
  {
    *timeout = true;
  }
  else if(pfd[0].revents & POLLIN)
  {
    *timeout = false;
    read(simulator->fd_ctl_from_simulator, exit_info,sizeof(EXIT_INFO));
  } 
  simulator->status = STATUS_FREE;
  simulator->state->total_exec++;
}
void fuzz_terminate(Simulator *simulator)
{
  CMD_INFO cmd_info;
  cmd_info.cmd = CMD_TERMINATE;

  int ret = write(simulator->fd_ctl_to_simulator, &cmd_info,sizeof(CMD_INFO));
  simulator->status = STATUS_EXIT;


}
void wait_forkserver_terminate(Simulator * simulator)
{
  EXIT_INFO exit_info;
  bool timeout = false;
  while(true)
  {
    fuzz_exit_timeout(simulator,&exit_info,5,&timeout);
    if(timeout)
      break;
    else if(exit_info.exit_code == EXIT_TERMINATE)
      break;
  }
}
Simulator* get_avaliable_simulator(FuzzState *state)
{
  bool should_continue = false;
  int ret,i;
  Simulator *simulator = nullptr;
  for(i = 0 ; i < state->simulators->size(); i++)
  {
    if((*state->simulators)[i]->status == STATUS_FREE)
    {
      return (*state->simulators)[i];
    }
      
  }
  while(1)
  {
    ret = poll(state->fds, state->num_fds, -1);
    if(ret == -1 && errno == EINTR)
      continue;
    else if(ret == -1)
      fatal("poll error\n");
    break;
  }
    

  
  
  if (ret == -1) fatal("poll error");
  for (i = 0; i < state->num_fds; i++) 
  {
    if (state->fds[i].revents & POLLIN) 
    {
      fuzz_one_post(state,(*state->simulators)[i]);
      return (*state->simulators)[i];
    }
  }
  fatal("no avaliable simulator\n");
  return nullptr;
}
void simulator_classify_count(Simulator * simulator)
{
  classify_counts((u64*)simulator->trace_bits,simulator->map_size);
}
void simulator_env_init(void)
{
  init_count_class16();
}
