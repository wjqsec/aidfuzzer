#include "stream_loader.h"
void save_pool(FuzzState *state,char *queue_dir)
{
  if(state->shared_stream_used == 0)
    return;
  char filename[PATH_MAX];
  sprintf(filename,"%s/%s",queue_dir,STREAM_POOL_FILENAME);
  FILE *f_pool = fopen(filename,"wb");
  fwrite(state->shared_stream_data,state->shared_stream_used,1,f_pool);
  fclose(f_pool);
}
void load_pool(FuzzState *state,char *queue_dir)
{
  char filename[PATH_MAX];
  struct stat st;
  sprintf(filename,"%s/%s",queue_dir,STREAM_POOL_FILENAME);
  FILE *f_pool = fopen(filename,"rb");
  if(!f_pool)
    return;
  stat(filename, &st);
  s32 size = st.st_size;
  fread(state->shared_stream_data,size,1,f_pool);
  fclose(f_pool);
  update_stream_ptr(state, size);
}

void save_queue(queue_entry *q,char *dir)
{
  char filename[PATH_MAX];
  sprintf(filename,"%s/queue_%08x",dir,q->cksum);
  FILE *f_queue = fopen(filename,"wb");
  fwrite(&q->depth,sizeof(q->depth),1,f_queue);
  fwrite(&q->edges,sizeof(q->edges),1,f_queue);
  fwrite(&q->cksum,sizeof(q->cksum),1,f_queue);
  fwrite(&q->priority,sizeof(q->priority),1,f_queue);
  for(auto it = q->streams->begin(); it != q->streams->end();it++)
  {
    fwrite(&it->second->priority,sizeof(it->second->priority),1,f_queue);
    fwrite(&it->second->offset_to_stream_area,sizeof(it->second->offset_to_stream_area),1,f_queue);
  }
  fclose(f_queue);
}
void save_crash(queue_entry *q,char *crash_dir)
{
  save_queue(q,crash_dir);
}
queue_entry *load_queue(FuzzState *state,char *seedfile)
{
  queue_entry *q = copy_queue(nullptr);
  input_stream *stream;
  FILE *f_queue = fopen(seedfile,"rb");
  if(!f_queue)
    fatal("queue file doesnt exist\n");
  fread(&q->depth,sizeof(q->depth),1,f_queue);
  fread(&q->edges,sizeof(q->edges),1,f_queue);
  fread(&q->cksum,sizeof(q->cksum),1,f_queue);
  fread(&q->priority,sizeof(q->priority),1,f_queue);
  while(1)
  {
    stream = new input_stream();
    if(!fread(&stream->priority,sizeof(stream->priority),1,f_queue))
      break;
    fread(&stream->offset_to_stream_area,sizeof(stream->offset_to_stream_area),1,f_queue);
    stream->ptr = (stream_metadata*) (state->shared_stream_data + stream->offset_to_stream_area);
    (*q->streams)[stream->ptr->stream_id] = stream;
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
      fwrite(&stream->priority,sizeof(stream->priority),1,f_freed_streams);
      fwrite(&stream->offset_to_stream_area,sizeof(stream->offset_to_stream_area),1,f_freed_streams);
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
    if(!fread(&stream->priority,sizeof(stream->priority),1,f_freed_streams))
      break;
    fread(&stream->offset_to_stream_area,sizeof(stream->offset_to_stream_area),1,f_freed_streams);
    stream->ptr = (stream_metadata*) (state->shared_stream_data + stream->offset_to_stream_area);
    free_stream(state,stream);
  }
  delete stream;
  fclose(f_freed_streams);
}