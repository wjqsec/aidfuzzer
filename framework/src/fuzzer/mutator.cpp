
#include "xx.h"
#include "iofuzzer.h"
#include "afl_utl.h"
#include "stream.h"

#define HAVOC_BLK_SMALL     16
#define HAVOC_BLK_MEDIUM    32
#define HAVOC_BLK_LARGE     64
#define HAVOC_BLK_XL        128
#define HAVOC_BLK_XXL        512

#define MAX_FILE            (5 * 1024)
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


input_stream* havoc(FuzzState *state,input_stream* stream)

{
  #define HAVOC_STACK 32
  #define HAVOC_TOKEN 18
  #define ARITH_MAX   35

  s32 len;
  u8 *data;
  input_stream * ret;
  u32 use_stacking;
  u32 max_num_element;
  s32 i;
  
  if(stream->ptr->mode == MODEL_CONSTANT || stream->ptr->mode == MODEL_PASSTHROUGH )
  {
    return extend_stream(state,stream,(UR(5) + 1) * HAVOC_BLK_LARGE);
  }


  
  ret = clone_stream(state,stream);

  max_num_element = stream->ptr->len / stream->ptr->element_size;
    
  use_stacking = (1 << (1 + UR(7)));
  
  use_stacking = use_stacking < max_num_element ? use_stacking : max_num_element;


  len = ret->ptr->len;
  data = ret->ptr->data;
  
  


  for (i = 0; i < use_stacking; i++) 
  {
    
    switch (UR(HAVOC_TOKEN))
    {
      case 0:
      {
        FLIP_BIT(data,UR(len << 3));
        break;
      }
      case 1:
      {
        if(ret->ptr->element_size != 1) break;
        ((s8*)data)[UR(len)] = interesting_8[UR(sizeof(interesting_8))];
        break;
      }
      case 2:
      {
        if(ret->ptr->element_size != 2) break;
        if(len < 2)
          break;
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
      {
        if(ret->ptr->element_size != 4) break;
        if(len < 4)
          break;
        s32* tmp = (s32*)(data + (UR(len - 3) & 0xfffffffc));
        if (UR(2)) {
          *tmp = interesting_32[UR(sizeof(interesting_32) >> 2)];
        } else {
          *tmp = SWAP32(
            interesting_32[UR(sizeof(interesting_32) >> 2)]);
        }
        
        break;
      }
      case 4:
      {
        if(ret->ptr->element_size != 1) break;
        data[UR(len)] ^= 0xff;
        break;
      }
      case 5:
      {
        if(ret->ptr->element_size != 1) break;
        data[UR(len)] -= 1 + UR(ARITH_MAX);
        break;
      }
      case 6:
      {
        if(ret->ptr->element_size != 1) break;
        data[UR(len)] += 1 + UR(ARITH_MAX);
        break;
      }
      case 7:
      {
        if(ret->ptr->element_size != 2) break;
        if(len < 2)
          break;
        u32 pos = UR(len - 1) & 0xfffffffe;
        if (UR(2)) {

          *(u16*)(data + pos) -= 1 + UR(ARITH_MAX);

        } else {

          u16 num = 1 + UR(ARITH_MAX);

          *(u16*)(data + pos) =
            SWAP16(SWAP16(*(u16*)(data + pos)) - num);

        }
        break;
      }
      case 8:
      {
        if(ret->ptr->element_size != 2) break;
        if(len < 2)
          break;
        u32 pos = UR(len - 1) & 0xfffffffe;
        if (UR(2)) {

          *(u16*)(data + pos) += 1 + UR(ARITH_MAX);

        } else {

          u16 num = 1 + UR(ARITH_MAX);

          *(u16*)(data + pos) =
            SWAP16(SWAP16(*(u16*)(data + pos)) + num);

        }
        break;
      }
      case 9:
      {
        if(ret->ptr->element_size != 4) break;
        if(len < 4)
          break;
        u32 pos = UR(len - 3) & 0xfffffffc;
        if (UR(2)) {

          *(u32*)(data + pos) -= 1 + UR(ARITH_MAX);

        } else {

          u32 num = 1 + UR(ARITH_MAX);
          *(u32*)(data + pos) =
            SWAP32(SWAP32(*(u32*)(data + pos)) - num);

        }
        break;
      }
      case 10:
      {
        if(ret->ptr->element_size != 4) break;
        if(len < 4)
          break;
        u32 pos = UR(len - 3) & 0xfffffffc;
        if (UR(2)) {

          *(u32*)(data + pos) += 1 + UR(ARITH_MAX);

        } else {

          u32 num = 1 + UR(ARITH_MAX);

          *(u32*)(data + pos) =
            SWAP32(SWAP32(*(u32*)(data + pos)) + num);

        }
        break;
      }
      case 11:
      {
        if(ret->ptr->element_size != 1) break;
        data[UR(len)] ^= 1 + UR(255);
        break;
      }
      case 12:
      {
        if(ret->ptr->element_size != 2) break;
        if(len < 2)
          break;
        s16* tmp = (s16*)(data + (UR(len - 1) & 0xfffffffe));
        *tmp = UR(0x10000);
        break;
      }
      case 13:
      {
        if(ret->ptr->element_size != 4) break;
        if(len < 4)
          break;
        s32* tmp = (s32*)(data + (UR(len - 3) & 0xfffffffc));
        *tmp = UR(0xffffffff);
        break;
      }
      case 14:
      {
         if (len + HAVOC_BLK_XXL < MAX_FILE) {

          /* Clone bytes (75%) or insert a block of constant bytes (25%). */

          u8  actually_clone = UR(4);
          u32 clone_from, clone_to, clone_len;
          input_stream *new_stream;

          if (actually_clone) {

            clone_len  = choose_block_len(len,ret->ptr->element_size);
            clone_from = UR(len - clone_len + 1);

          } else {

            clone_len = choose_block_len(HAVOC_BLK_XXL,ret->ptr->element_size);
            clone_from = 0;

          }

          clone_to   = UR(len);

          new_stream = allocate_enough_space_stream(state,ret->ptr->stream_id,len+clone_len);

          /* Head */

          memcpy(new_stream->ptr->data, ret->ptr->data, clone_to);

          /* Inserted part */

          if (actually_clone)
            memcpy(new_stream->ptr->data + clone_to, ret->ptr->data + clone_from, clone_len);
          else
            memset(new_stream->ptr->data + clone_to,
                    UR(2) ? UR(256) : ret->ptr->data[UR(len)], clone_len);

          /* Tail */
          memcpy(new_stream->ptr->data + clone_to + clone_len, ret->ptr->data + clone_to,
                  len - clone_to);

          free_stream(state,ret);
          ret = new_stream;
          len = ret->ptr->len;
          data = ret->ptr->data;
        }
        break;
      }
      case 15:
      {
        u32 del_from, del_len;
        if (len <= ret->ptr->element_size) break;
        del_len = choose_block_len(0x20,ret->ptr->element_size);
        if(del_len == 0)  break;
        if (len < ret->ptr->element_size + del_len) break;
        del_from = UR(len - del_len + 1);
        memmove(data + del_from, data + del_from + del_len,
                  len - del_from - del_len);
        ret->ptr->len -= del_len;
        len  -= del_len;
        break;
      }

      case 16:
      {
        u32 copy_from, copy_to, copy_len;

        if (len < 2) break;

        copy_len  = choose_block_len(len - 1,ret->ptr->element_size);
        if (copy_len == 0) break; 
        copy_from = UR(len - copy_len + 1);
        copy_to   = UR(len - copy_len + 1);

        if (UR(4)) {

          if (copy_from != copy_to)
            memmove(ret->ptr->data + copy_to, ret->ptr->data + copy_from, copy_len);

        } else memset(ret->ptr->data + copy_to,
                      UR(2) ? UR(256) : ret->ptr->data[UR(len)], copy_len);
        break;
      }

      case 17:
      {
        if(ret->ptr->element_size != 1) break;
        data[UR(len)] = 0x20 + UR(0x7f - 0x20);
        break;
      }
      default:
      break;
    }
    
    
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