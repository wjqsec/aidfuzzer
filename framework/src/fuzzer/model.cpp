
#include "model.h"
#include "mis_utl.h"
#include <sys/types.h>
#include <dirent.h>
#include <linux/limits.h>
#include <string.h>
#include "fuzzer.h"

extern char  out_dir[PATH_MAX];
extern char  dump_backup_dir[PATH_MAX];
void run_modelling(FuzzState *state,uint32_t id)
{
  char cmd[PATH_MAX];
  char state_filename[PATH_MAX];
  #ifdef RUN_IN_DOCKER

  char model_filename[PATH_MAX];
  sprintf(state_filename,"%s/%s%08x",state->dir_info.state_dump_model_dir.c_str(), MMIO_STATE_PREFIX,id);
  sprintf(model_filename,"%s/%s",state->dir_info.state_dump_model_dir.c_str(),MMIO_MODEL_FILENAME);
  sprintf(cmd,"fuzzware model %s -c %s > /dev/null 2>&1",
  state_filename,
  model_filename);
  #else
  
  sprintf(state_filename,"%s%08x",MMIO_STATE_PREFIX,id);
  
  sprintf(cmd,"docker run -i --rm --mount type=bind,source=%s,target=/home/user/fuzzware/targets fuzzware:latest fuzzware model %s -c %s > /dev/null 2>&1",
  state->dir_info.state_dump_model_dir.c_str(),
  state_filename,
  MMIO_MODEL_FILENAME);
  
  #endif
  printf("start model file:%s\n",state_filename);
  system(cmd);
  printf("model file done\n");
}
void add_default_model(FuzzState *state,u32 id, u32 element_size, u32 mmio_pc, u32 mmio_addr)
{
  input_model *model = new input_model();
  model->mode = MODEL_NONE;
  model->access_size = element_size;
  model->mmio_addr = mmio_addr;
  model->pc_addr = mmio_pc;
  (*state->models)[id] = model;
}

void add_irq_model(FuzzState *state)
{
  input_model *model = new input_model();
  model->mode = MODEL_NONE;
  model->access_size = 1;
  model->mmio_addr = 0;
  model->pc_addr = 0;
  (*state->models)[IRQ_STREAM_ID] = model;
}
void sync_models(FuzzState *state)
{
  u32 mmio_id;
  int mode;
  char line[PATH_MAX];
  input_model *model = NULL;
  set<u32> *vals = NULL;
  FILE *fp = fopen(state->file_info.mmio_model_file.c_str() , "r");
  if(fp == NULL) 
  {
    return;
  }
  while(fgets(line, PATH_MAX, fp))
  {
    if(strstr(line,"unmodeled:"))
      mode = MODEL_NONE;
    if(strstr(line,"constant:"))
      mode = MODEL_CONSTANT;
    if(strstr(line,"set:"))
      mode = MODEL_VALUE_SET;
    if(strstr(line,"passthrough:"))
      mode = MODEL_PASSTHROUGH;
    if(strstr(line,"bitextract:"))
      mode = MODEL_BIT_EXTRACT;

    if(char *mmio_str = strstr(line,"_mmio_"))
    {
      u32 mmio_addr = strtol(mmio_str + strlen("_mmio_"), 0, 16);
      u32 mmio_pc = strtol(strstr(line,"pc_") + strlen("pc_"), 0, 16);
      mmio_id = hash_32_ext(mmio_addr) ^ hash_32_ext(mmio_pc);
      
      if(mode == MODEL_VALUE_SET)
      {
        vals = new set<u32>();
      }
      else
      {
        vals = nullptr;
      }
      if(state->models->find(mmio_id) != state->models->end())
      {
        if((*state->models)[mmio_id]->values != nullptr)
          delete (*state->models)[mmio_id]->values;
        delete (*state->models)[mmio_id];
      }
      model = new input_model();
      model->mode = mode;
      model->values = vals;

      model->mmio_addr = mmio_addr;
      model->pc_addr = mmio_pc;
      (*state->models)[mmio_id] = model;
    }
    
    if(strstr(line,"access_size: "))
      model->access_size = strtol(strstr(line,"access_size: ") + strlen("access_size: "), 0, 16);
    if(strstr(line,"left_shift: "))
      model->left_shift = strtol(strstr(line,"left_shift: ") + strlen("left_shift: "),0,16);
    if(strstr(line,"mask: "))
      model->mask = strtol(strstr(line,"mask: ") + strlen("mask: "),0,16);
    if(strstr(line,"size: ") && !strstr(line,"access_size: "))
      model->size = strtol(strstr(line,"size: ") + strlen("size: "),0,16);
    if(strstr(line,"init_val: "))
      model->init_val = strtol(strstr(line,"init_val: ") + strlen("init_val: "),0,16);
    if(strstr(line,"val: ") && !strstr(line,"init_val: "))
      model->constant_val = strtol(strstr(line,"val: ") + strlen("val: "),0,16);
    if(strstr(line,"- "))
      vals->insert(strtol(strstr(line,"- ") + strlen("- "),0,16));
  }

  fclose(fp);
}
