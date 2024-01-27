#include <stdio.h>
#include "simulator.h"
#include "iofuzzer.h"
#include "afl_utl.h"
#include <string.h>
#include <unistd.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include "mis_utl.h"
#include <vector>
#include <set>
#include <map>
#include <poll.h>
#include <sched.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <string.h>
#include <algorithm>         /* Definition of AT_* constants */
#include <random>
#include <sys/syscall.h>      /* Definition of SYS_* constants */
#include <dirent.h>
#include <sys/time.h>
#include <sys/shm.h>
#include <fcntl.h>              /* Definition of O_* constants */
#include <sys/stat.h>
#include <execinfo.h>
#include <stdarg.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>
#include <stdio.h>


#include "model.h"
void simulator_task(Simulator *simulator,queue_entry* fuzz_entry,queue_entry* base_entry, set<u32> *fuzz_streams)
{
  simulator->task.fuzz_entry = fuzz_entry;
  simulator->task.base_entry = base_entry;
  simulator->task.fuzz_streams = fuzz_streams;
}
void copy_fuzz_data(Simulator *simulator)
{
  int i = 0;
  simulator->task.id_queue_idx_mapping->clear();
  map<u32,input_stream *> *streams;
  fuzz_queue *queue = (fuzz_queue *)simulator->shared_fuzz_queue_data;
  streams = simulator->task.fuzz_entry->streams;
  queue->num_streams = streams->size();


  for(auto it = streams->begin(); it != streams->end(); it++)
  {
    queue->streams[i].offset_to_stream_area = it->second->offset_to_stream_area;
    queue->streams[i].used = 0;
    (*simulator->task.id_queue_idx_mapping)[it->first] = i;
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
EXIT_INFO run_input(FuzzState *state,queue_entry* fuzz_entry,Simulator **out_simulator)
{

  EXIT_INFO exit_info;
  Simulator *simulator;

  simulator = get_avaliable_simulator(state);  
  simulator_task(simulator,fuzz_entry,0,0);
  fuzz_start(simulator);
  fuzz_exit(simulator,&exit_info);
  simulator_classify_count(simulator);
  if (out_simulator)
    *out_simulator = simulator;
  return exit_info;
}
void fuzz_continue_stream_notfound(Simulator *simulator,input_stream *new_stream)
{
  CMD_INFO cmd_info;
  cmd_info.cmd = CMD_CONTINUE_ADD_STREAM;
  fuzz_queue *queue = (fuzz_queue *)simulator->shared_fuzz_queue_data;

 

  cmd_info.added_stream_index = queue->num_streams;
  
  queue->streams[queue->num_streams].offset_to_stream_area = new_stream->offset_to_stream_area;

  queue->streams[queue->num_streams].used = 0;

  (*simulator->task.id_queue_idx_mapping)[new_stream->ptr->stream_id] = queue->num_streams;

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
  idx = (*simulator->task.id_queue_idx_mapping)[new_stream->ptr->stream_id];
  queue->streams[idx].offset_to_stream_area = new_stream->offset_to_stream_area;
  cmd_info.updated_stream_index = idx;
  write(simulator->fd_ctl_to_simulator, &cmd_info,sizeof(CMD_INFO));
  simulator->status = STATUS_RUNNING;

}
void fuzz_exit(Simulator *simulator,EXIT_INFO *exit_info)
{
  read(simulator->fd_ctl_from_simulator, exit_info,sizeof(EXIT_INFO));
  
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
}
void fuzz_terminate(Simulator *simulator)
{
  CMD_INFO cmd_info;
  cmd_info.cmd = CMD_TERMINATE;

  int ret = write(simulator->fd_ctl_to_simulator, &cmd_info,sizeof(CMD_INFO));
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
    else if(exit_info.exit_code == EXIT_CTL_TERMINATE)
      break;
  }
  simulator->status = STATUS_EXIT;
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
    
  for (i = 0; i < state->num_fds; i++) 
  {
    if (state->fds[i].revents & POLLIN) 
    {
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
void clean_simualtor_shm(Simulator * simulator)
{

  shmdt(simulator->trace_bits);
  shmdt(simulator->shared_fuzz_queue_data);

  shmctl(simulator->shm_id_trace_bit, IPC_RMID, 0);
  shmctl(simulator->shm_id_fuzz_queue, IPC_RMID, 0);
}
void kill_simulator(Simulator * simulator)
{
  int status;
  kill(simulator->pid,SIGKILL);
  waitpid(simulator->pid,&status,WEXITED | WSTOPPED);
  printf("simualtor pid:%d killed\n",simulator->pid);
  simulator->status = STATUS_KILLED;
}
void wait_all_simualtor_finish_task(FuzzState *state)
{
  EXIT_INFO exit_info;
  for(auto s = state->simulators->begin(); s != state->simulators->end(); s++)
  {
    if((*s)->status == STATUS_FREE)
      continue;
    fuzz_exit(*s,&exit_info);
  }
}
void kill_cleanup_simulator(FuzzState *state,int pid)
{
  int status;
  for(Simulator * simulator : (*state->simulators))
  {
    if(simulator->pid != pid)
      continue;
    kill_simulator(simulator);
    clean_simualtor_shm(simulator);
  }
}
void allocate_new_simulator(FuzzState *state, int affinity)
{
  static int start_fd = 100;
  static int cpu = 0;
  int status;
  int i;
  pid_t pid;
  int st_pipe[2], ctl_pipe[2];
  char shm_str[PATH_MAX];
  EXIT_INFO exit_info;

  Simulator *simulator = new Simulator();
  simulator->map_size = state->map_size;
  simulator->task.id_queue_idx_mapping = new map<u32,int>();

  simulator->shm_id_trace_bit = shmget(IPC_PRIVATE, simulator->map_size, IPC_CREAT | IPC_EXCL | 0600);
  if (simulator->shm_id_trace_bit < 0) 
      fatal("shmget() failed");
  sprintf(shm_str,"%d",simulator->shm_id_trace_bit);
  setenv(SHM_ENV_VAR, shm_str, 1);
  simulator->trace_bits = (u8*)shmat(simulator->shm_id_trace_bit, NULL, 0);
  if (simulator->trace_bits == (void *)-1) 
      fatal("shmat() failed");

  simulator->shm_id_fuzz_queue = shmget(IPC_PRIVATE, SHARE_FUZZQUEUE_SIZE, IPC_CREAT | IPC_EXCL | 0600);
  if (simulator->shm_id_fuzz_queue < 0) 
      fatal("shmget() failed");
  sprintf(shm_str,"%d",simulator->shm_id_fuzz_queue);
  setenv(SHM_SHARE_FUZZ_QUEUE_VAR, shm_str, 1);
  simulator->shared_fuzz_queue_data = (u8*)shmat(simulator->shm_id_fuzz_queue, NULL, 0);
  if (simulator->shared_fuzz_queue_data == (void *)-1) 
      fatal("shmat() failed");

  if (pipe(st_pipe) || pipe(ctl_pipe)) fatal("pipe() failed");
  if (dup2(ctl_pipe[0], start_fd) < 0) fatal("dup2() failed");
  if (dup2(st_pipe[1], start_fd + 1) < 0) fatal("dup2() failed");

  
  simulator->fd_ctl_to_simulator = ctl_pipe[1];
  simulator->fd_ctl_from_simulator = st_pipe[0];

  state->fds[state->num_fds].fd = simulator->fd_ctl_from_simulator;
  state->fds[state->num_fds].events = POLLIN;
  state->fds[state->num_fds].revents = 0;
  
	char *child_arg[1000];
  i = 0;
  child_arg[i++] = strdup(state->file_info.simulator_bin.c_str());

  char *simulator_log_dir = alloc_printf("%s/simulator_%d",state->dir_info.simulator_log_dir.c_str(),cpu);
  mkdir(simulator_log_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);


  child_arg[i++] =  strdup(state->dir_info.state_dump_model_dir.c_str());

  child_arg[i++] = strdup(state->dir_info.state_dump_model_dir.c_str());

  child_arg[i++] = simulator_log_dir;

  child_arg[i++] = alloc_printf("%d",start_fd);

  child_arg[i++] = alloc_printf("%d",start_fd + 1);

  child_arg[i++] =  strdup(state->file_info.config.c_str());

  child_arg[i++] = (char*)"-cov";
  child_arg[i++] =  strdup(state->file_info.cov_log.c_str());

  child_arg[i++] = (char*)"-filter";
  child_arg[i++] =  strdup(state->file_info.valid_bbl.c_str());
  


  child_arg[i++] = NULL;

  cpu_set_t parentMask;
  if(affinity != -1)
  {
    CPU_ZERO(&parentMask);
    CPU_SET(affinity, &parentMask);
    sched_setaffinity(0, sizeof(parentMask), &parentMask);
  }

  pid = fork();
	if (pid < 0) fatal("fork error\n");
	else if(!pid)
	{
    if(affinity != -1)
      sched_setaffinity(0, sizeof(parentMask), &parentMask);
		execv(child_arg[0],child_arg);
	}
  
  simulator->pid = pid;
  simulator->cpu = cpu;
  simulator->status = STATUS_FREE;

  state->simulators->push_back(simulator);

  printf("pid:%d wait for fork server\n",simulator->pid);
      

  fuzz_exit(simulator,&exit_info);

  if(exit_info.exit_code != EXIT_CTL_FORKSRV_UP)
  {
    printf("fork server is not up got %s pc: %x lr:%x\n",fuzzer_exit_names[exit_info.exit_code],exit_info.exit_pc,exit_info.exit_lr);
    kill_cleanup_simulator(state,pid);
    clean_fuzzer_shm(state);
    exit(0);
  }
  printf("pid:%d fork server is up\n",simulator->pid);
  simulator_classify_count(simulator);
  update_virgin(state->virgin_bits, simulator->trace_bits, simulator->map_size);

  
  start_fd += 2;
  cpu++;
  state->num_fds++;
}
