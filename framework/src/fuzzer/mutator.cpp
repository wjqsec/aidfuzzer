
#include "xx.h"
#include "iofuzzer.h"
#include "afl_utl.h"
#include "stream.h"

#define HAVOC_BLK_SMALL     16
#define HAVOC_BLK_MEDIUM    32
#define HAVOC_BLK_LARGE     128
#define HAVOC_BLK_XL        1024
#define HAVOC_BLK_XXL        2048

#define MAX_FILE            (100 * 1024)
#ifndef MIN
#  define MIN(_a,_b) ((_a) > (_b) ? (_b) : (_a))
#  define MAX(_a,_b) ((_a) > (_b) ? (_a) : (_b))
#endif /* !MIN */
#define SWAP16(_x) ({ \
    u16 _ret = (_x); \
    (u16)((_ret << 8) | (_ret >> 8)); \
  })

#define SWAP32(_x) ({ \
    u32 _ret = (_x); \
    (u32)((_ret << 24) | (_ret >> 24) | \
          ((_ret << 8) & 0x00FF0000) | \
          ((_ret >> 8) & 0x0000FF00)); \
  })

#define FLIP_BIT(_ar, _b) do { \
    u8* _arf = (u8*)(_ar); \
    u32 _bf = (_b); \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf) & 7)); \
  } while (0)


static u32 choose_block_len(u32 limit,u32 align) {

  u32 ret;
  u32 min_value, max_value;
  u32 rlim = 4;


  switch (UR(rlim)) {

    case 0:  min_value = 1;
             max_value = HAVOC_BLK_SMALL;
             break;

    case 1:  min_value = HAVOC_BLK_SMALL;
             max_value = HAVOC_BLK_MEDIUM;
             break;
    case 2:  min_value = HAVOC_BLK_MEDIUM;
             max_value = HAVOC_BLK_LARGE;
             break;
    default: 

             if (UR(5)) {

               min_value = HAVOC_BLK_LARGE;
               max_value = HAVOC_BLK_XL;

             } else {

               min_value = HAVOC_BLK_XL;
               max_value = HAVOC_BLK_XXL;

             }

  }

  if (min_value >= limit) min_value = 1;

  ret = min_value + UR(MIN(max_value, limit) - min_value + 1);
  return (ret / align) * align;

}

static void locate_diffs(u8* ptr1, u8* ptr2, u32 len, s32* first, s32* last) {

  s32 f_loc = -1;
  s32 l_loc = -1;
  u32 pos;

  for (pos = 0; pos < len; pos++) {

    if (*(ptr1++) != *(ptr2++)) {

      if (f_loc == -1) f_loc = pos;
      l_loc = pos;

    }

  }

  *first = f_loc;
  *last = l_loc;

  return;

}




input_stream* increase_stream(FuzzState *state,input_stream* stream)
{

  s32 incease_len;
  input_stream* ret;
  s32 len = stream->ptr->len;
  if (len + HAVOC_BLK_XXL < MAX_FILE) 
  {
    incease_len = choose_block_len(HAVOC_BLK_XXL,stream->ptr->element_size);
  }
  else
    incease_len = 0;
  
  ret =  extend_stream(state,stream, incease_len);

  return ret;
  
}






inline input_stream* havoc_flip_bit(FuzzState *state,input_stream* stream)
{
  u8 *data = stream->ptr->data;
  s32 len = stream->ptr->len;
  FLIP_BIT(data,UR(len << 3));
  return stream;
}
inline input_stream* havoc_arith(FuzzState *state,input_stream* stream)
{
  #define ARITH_MAX   35
  u8 *data = stream->ptr->data;
  s32 len = stream->ptr->len;
  switch(stream->ptr->element_size)
  {
    case 1:
    {
      if(UR(2)) {
        data[UR(len)] -= 1 + UR(ARITH_MAX);
      }
      else{
        data[UR(len)] += 1 + UR(ARITH_MAX);
      }
      break;
    }
    case 2:
    {
      u32 pos = UR(len - 1) & 0xfffffffe;
      if(UR(2)) {
        if (UR(2)) {
          *(u16*)(data + pos) -= 1 + UR(ARITH_MAX);
        } else {
          u16 num = 1 + UR(ARITH_MAX);
          *(u16*)(data + pos) =
            SWAP16(SWAP16(*(u16*)(data + pos)) - num);
        }
      }
      else{
        if (UR(2)) {

          *(u16*)(data + pos) += 1 + UR(ARITH_MAX);

        } else {

          u16 num = 1 + UR(ARITH_MAX);

          *(u16*)(data + pos) =
            SWAP16(SWAP16(*(u16*)(data + pos)) + num);

        }

      }
      break;
    }
    case 3:
    case 4:
    {
      u32 pos = UR(len - 3) & 0xfffffffc;
      if(UR(2)){
        if (UR(2)) {

          *(u32*)(data + pos) -= 1 + UR(ARITH_MAX);

        } else {

          u32 num = 1 + UR(ARITH_MAX);
          *(u32*)(data + pos) =
            SWAP32(SWAP32(*(u32*)(data + pos)) - num);
        }
      } else{
        if (UR(2)) {

          *(u32*)(data + pos) += 1 + UR(ARITH_MAX);

        } else {

          u32 num = 1 + UR(ARITH_MAX);

          *(u32*)(data + pos) =
            SWAP32(SWAP32(*(u32*)(data + pos)) + num);

        }
      }
      break;
    }
    default:
    {
      break;
    }
  }
  return stream;
}
inline input_stream* havoc_interesting_value(FuzzState *state,input_stream* stream)
{
  u8 *data = stream->ptr->data;
  s32 len = stream->ptr->len;
  switch(stream->ptr->element_size)
  {
    case 1:
    {
      ((s8*)data)[UR(len)] = interesting_8[UR(sizeof(interesting_8))];  
      break;
    }
    case 2:
    {
      s16* tmp = (s16*)(data + (UR(len - 1) & 0xfffffffe));
      if (UR(2)) {
        *tmp = interesting_16[UR(sizeof(interesting_16) >> 1)];
      } else {
        *tmp = SWAP16(
        interesting_16[UR(sizeof(interesting_16) >> 1)]);
      }
      break;
    }
    case 3:
    case 4:
    {
      s32* tmp = (s32*)(data + (UR(len - 3) & 0xfffffffc));
      if (UR(2)) {
          *tmp = interesting_32[UR(sizeof(interesting_32) >> 2)];
        } else {
          *tmp = SWAP32(
            interesting_32[UR(sizeof(interesting_32) >> 2)]);
        }
      break;
    }
    default:
    {
      break;
    }
  }
  return stream;
}
inline input_stream* havoc_insert(FuzzState *state,input_stream* stream)
{
  u8 *data = stream->ptr->data;
  s32 len = stream->ptr->len;
  input_stream* ret = stream;
  if (len + HAVOC_BLK_XXL < MAX_FILE) {

          /* Clone bytes (75%) or insert a block of constant bytes (25%). */

          u8  actually_clone = UR(4);
          u32 clone_from, clone_to, clone_len;
          input_stream *new_stream;

          if (actually_clone) {

            clone_len  = choose_block_len(len,stream->ptr->element_size);
            clone_from = UR(len - clone_len + 1);

          } else {

            clone_len = choose_block_len(HAVOC_BLK_XXL,stream->ptr->element_size);
            clone_from = 0;

          }

          clone_to   = UR(len);

          new_stream = allocate_enough_space_stream(state,stream->ptr->stream_id,len+clone_len);

          /* Head */

          memcpy(new_stream->ptr->data, data, clone_to);

          /* Inserted part */

          if (actually_clone)
            memcpy(new_stream->ptr->data + clone_to, data + clone_from, clone_len);
          else
            memset(new_stream->ptr->data + clone_to,
                    UR(2) ? UR(256) : data[UR(len)], clone_len);

          /* Tail */
          memcpy(new_stream->ptr->data + clone_to + clone_len, data + clone_to,
                  len - clone_to);

          free_stream(state,stream);
          ret = new_stream;
        }
    return ret;
}
inline input_stream* havoc_delete(FuzzState *state,input_stream* stream)
{
  u8 *data = stream->ptr->data;
  s32 len = stream->ptr->len;

  u32 del_from, del_len;
  if (len <= stream->ptr->element_size) return stream;
  del_len = choose_block_len(0x20,stream->ptr->element_size);
  if(del_len == 0)  return stream;
  if (len < stream->ptr->element_size + del_len) return stream;
  del_from = UR(len - del_len + 1);
  memmove(data + del_from, data + del_from + del_len,
            len - del_from - del_len);
  stream->ptr->len -= del_len;
  return stream;
}
inline input_stream* havoc_revert(FuzzState *state,input_stream* stream)
{
  u8 *data = stream->ptr->data;
  s32 len = stream->ptr->len;
  data[UR(len)] ^= 0xff;
  return stream;
}
inline input_stream* havoc_random(FuzzState *state,input_stream* stream)
{
  u8 *data = stream->ptr->data;
  s32 len = stream->ptr->len;
  switch(stream->ptr->element_size)
  {
    case 1:
    {
      data[UR(len)] = UR(0x100);
      break;
    }
    case 2:
    {
      s16* tmp = (s16*)(data + (UR(len - 1) & 0xfffffffe));
      *tmp = UR(0x10000);
      break;
    }
    case 3:
    case 4:
    {
      s32* tmp = (s32*)(data + (UR(len - 3) & 0xfffffffc));
      *tmp = UR(0xffffffff);
      break;
    }
    default:
    {
      break;
    }
  }
  return stream;
}
inline input_stream* havoc_ascii(FuzzState *state,input_stream* stream)
{
  u8 *data = stream->ptr->data;
  s32 len = stream->ptr->len;
  switch(stream->ptr->element_size)
  {
    case 1:
    {
      data[UR(len)] = 0x20 + UR(0x7f - 0x20);
      break;
    }
    case 2:
    {
      s16* tmp = (s16*)(data + (UR(len - 1) & 0xfffffffe));
      *tmp = 0x20 + UR(0x7f - 0x20);
      break;
    }
    case 3:
    case 4:
    {
      s32* tmp = (s32*)(data + (UR(len - 3) & 0xfffffffc));
      *tmp = 0x20 + UR(0x7f - 0x20);
      break;
    }
    default:
    {
      break;
    }
  }
  return stream;
}
inline input_stream* havoc_splicing_copy(FuzzState *state,input_stream* stream)
{
  u8 *data = stream->ptr->data;
  s32 len = stream->ptr->len;
  u32 copy_from, copy_to, copy_len;

  if ( len < 2) return stream;

  copy_len  = choose_block_len(len - 1,stream->ptr->element_size);
  if (copy_len == 0) return stream; 
  copy_from = UR(len - copy_len + 1);
  copy_to   = UR(len - copy_len + 1);

  if (UR(4)) {

    if (copy_from != copy_to)
      memmove(data + copy_to, data + copy_from, copy_len);

  } else memset(data + copy_to,
                UR(2) ? UR(256) : data[UR(len)], copy_len);
  return stream;      
}

typedef input_stream* (*havoc_fuc) (FuzzState *state,input_stream* stream);

static havoc_fuc havoc_arrays[] = { havoc_flip_bit, 
                                    havoc_interesting_value, 
                                    havoc_insert,
                                    havoc_delete,
                                    havoc_revert,
                                    havoc_random,
                                    havoc_ascii,
                                    havoc_splicing_copy};

input_stream* havoc(FuzzState *state,input_stream* stream)
{
  input_stream * ret;
  u32 use_stacking;
  s32 i;
  

  ret = clone_stream(state,stream);


  use_stacking = (1 << (1 + UR(6)));

  for (i = 0; i < use_stacking; i++) 
  {
    ret = havoc_arrays[UR(sizeof(havoc_arrays) / sizeof(havoc_arrays[0]))](state,ret);
  }
  return ret;
  
}



// input_stream* splicing(FuzzState *state,input_stream* stream)
// {
//   s32 len;
//   u8 *data;
//   s32 f_diff, l_diff,split_at;
//   input_stream * ret;
//   input_stream* target;
//   vector<input_stream *> *queue_streams;

  
//   if(state->all_queued_streams->count(stream->ptr->stream_id) == 0)
//   {
//     return nullptr;
//   }
//   queue_streams = (*state->all_queued_streams)[stream->ptr->stream_id];
//   if(queue_streams->size() <= 1)
//     return nullptr;
//   target = (*queue_streams)[UR(queue_streams->size())];
//   if(target == stream)
//     return nullptr;
//   ret = clone_stream(state,stream);
//   len = ret->ptr->len;
//   data = ret->ptr->data;

//   locate_diffs(data, target->ptr->data, MIN(len, target->ptr->len), &f_diff, &l_diff);

//   if (f_diff < 0 || l_diff < 2 || f_diff == l_diff) 
//   {
//     return ret;
//   }
//   split_at = f_diff + UR(l_diff - f_diff);
//   memcpy(data, target->ptr->data, split_at);
//   return ret;
// }