#include "stream_loader.h"


void save_pool_file(FuzzState *state,char *filename)
{
  FILE *f_pool = fopen(filename,"wb");
  fwrite(state->shared_stream_data,state->shared_stream_used,1,f_pool);
  fclose(f_pool);
}
void load_pool_file(FuzzState *state,char *filename)
{
  struct stat st;
  FILE *f_pool = fopen(filename,"rb");
  if(!f_pool)
    return;
  stat(filename, &st);
  s32 size = st.st_size;
  fread(state->shared_stream_data,size,1,f_pool);
  fclose(f_pool);
  update_stream_ptr(state, size);
}
void save_default_pool(FuzzState *state,char *queue_dir)
{
  if(state->shared_stream_used == 0)
    return;
  char filename[PATH_MAX];
  sprintf(filename,"%s/%s",queue_dir,STREAM_POOL_FILENAME);
  save_pool_file(state,filename);
  
}
void load_default_pool(FuzzState *state,char *queue_dir)
{
  char filename[PATH_MAX];
  
  sprintf(filename,"%s/%s",queue_dir,STREAM_POOL_FILENAME);
  load_pool_file(state,filename);
}

void save_crash_pool(FuzzState *state,char *crash_dir, u32 id)
{
  char filename[PATH_MAX];
  sprintf(filename,"%s/pool_%x.bin",crash_dir,id);
  save_pool_file(state,filename);
}
void load_crash_pool(FuzzState *state,char *filename)
{
  load_pool_file(state,filename);
}
void save_queue(queue_entry *q,char *dir)
{
  char filename[PATH_MAX];
  sprintf(filename,"%s/queue_%08x",dir,q->cksum);
  FILE *f_queue = fopen(filename,"wb");
  fwrite(q,offsetof(queue_entry,offset_to_save),1,f_queue);
  for(auto it = q->streams->begin(); it != q->streams->end();it++)
  {
    fwrite(it->second,offsetof(input_stream,offset_to_save),1,f_queue);
  }
  fclose(f_queue);
}
void save_crash(queue_entry *q,char *crash_dir)
{
  save_queue(q,crash_dir);
}
queue_entry *load_queue(FuzzState *state,char *seedfile)
{
  queue_entry *q = copy_queue(state,nullptr);
  input_stream *stream;
  FILE *f_queue = fopen(seedfile,"rb");
  if(!f_queue)
    fatal("queue file doesnt exist\n");
  fread(q,offsetof(queue_entry,offset_to_save),1,f_queue);

  while(1)
  {
    stream = new input_stream();
    if(!fread(stream,offsetof(input_stream,offset_to_save),1,f_queue))
      break;
    stream->ptr = (stream_metadata*) (state->shared_stream_data + stream->offset_to_stream_area);
    insert_stream(state,q,stream,true);
  }
  delete stream;
  fclose(f_queue);
  return q;
}

void save_queues(FuzzState *state,char *queue_dir)
{
  for(queue_entry *q : *state->entries)
  {
    save_queue(q,queue_dir);
  }
}

void load_queues(FuzzState *state,char *queue_dir)
{
  u32 cksum;
  DIR* dir;
  struct dirent* dir_entry;
  queue_entry *q;
  char filename[PATH_MAX];
  


  dir = opendir(queue_dir);
  if (dir == NULL) {
    fatal("opendir error");
  }
  
  while ((dir_entry = readdir(dir)) != NULL) 
  {
    if (dir_entry->d_type == DT_REG  && strstr(dir_entry->d_name,"queue_")) 
    {
      sprintf(filename,"%s/%s",queue_dir,dir_entry->d_name);
      q = load_queue(state,filename);
      insert_queue(state, q);
    }
  }
  closedir(dir);
}
void clean_queues(FuzzState *state,char *queue_dir)
{
  char cmd[PATH_MAX];
  sprintf(cmd,"rm -rf %s/*",queue_dir);
  system(cmd);
}
void save_freed_streams(FuzzState *state,char *queue_dir)
{
  char filename[PATH_MAX];
  sprintf(filename,"%s/%s",queue_dir,FREED_STREAMS_FILENAME);
  FILE *f_freed_streams = fopen(filename,"wb");
  vector<input_stream*>* streams;
  for(auto it = state->freed_streams->begin(); it != state->freed_streams->end(); it++)
  {
    streams = it->second;
    for(input_stream* stream: *streams)
    {
      fwrite(stream,offsetof(input_stream,offset_to_save),1,f_freed_streams);
    }
  }
  fclose(f_freed_streams);
}
void load_freed_streams(FuzzState *state,char *queue_dir)
{
  char filename[PATH_MAX];
  sprintf(filename,"%s/%s",queue_dir,FREED_STREAMS_FILENAME);
  FILE *f_freed_streams = fopen(filename,"rb");
  if(!f_freed_streams)
    return;
  input_stream* stream;
  while(true)
  {
    stream = new input_stream();
    if(!fread(stream,offsetof(input_stream,offset_to_save),1,f_freed_streams))
      break;
    stream->ptr = (stream_metadata*) (state->shared_stream_data + stream->offset_to_stream_area);
    free_stream(state,stream);
  }
  delete stream;
  fclose(f_freed_streams);
}