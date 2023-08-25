
#include "model.h"
#include "afl_utl.h"
#include <sys/types.h>
#include <dirent.h>
#include <linux/limits.h>
#include <string.h>

extern char  *out_dir;
extern char  dump_backup_dir[PATH_MAX];
void run_modelling(FuzzState *state,Simulator *simulator)
{
  DIR* dir;
  char cmd[PATH_MAX];
  char tmp[PATH_MAX];
  struct dirent* dir_entry;
  dir = opendir(simulator->simulator_dump_dir);
  if (dir == NULL) {
      fatal("opendir error");
  }
  
  while ((dir_entry = readdir(dir)) != NULL) 
  {
    if (dir_entry->d_type == DT_REG  && strstr(dir_entry->d_name,MMIO_STATE_PREFIX)) 
    {
      u32 id = strtol(dir_entry->d_name + strlen(MMIO_STATE_PREFIX),0,16);
      if(state->models->find(id) == state->models->end())
      {
        printf("start model file:%s\n",dir_entry->d_name);
        sprintf(cmd,"%s/run_docker.sh %s fuzzware model ./dump/simulator_%d/%s -c ./model/simulator_%d/%s > /dev/null",
        FUZZWARE_PATH,
        out_dir,
        simulator->cpu,
        dir_entry->d_name,
        simulator->cpu,
        MMIO_MODEL_FILENAME);
        system(cmd);
        printf("model file done:%s\n",dir_entry->d_name);
      }
      sprintf(cmd,"mv %s/%s %s/",simulator->simulator_dump_dir,dir_entry->d_name,dump_backup_dir);
      system(cmd);
    }
  }
  closedir(dir);
}
void sync_models(FuzzState *state,Simulator *simulator)
{
  u32 mmio_id;
  int mode;
  char line[PATH_MAX];
  input_model *model = NULL;
  set<u32> *vals = NULL;
  sprintf(line,"%s/%s",simulator->simulator_model_dir,MMIO_MODEL_FILENAME);
  FILE *fp = fopen(line , "r");
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
      model = new input_model();
      model->mode = mode;
      model->values = vals;
      (*state->models)[mmio_id] = model;
      (*state->streamid_mmioaddr_mapping)[mmio_id] = mmio_addr;
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