
#include "xx.h"
#include "iofuzzer.h"
#include "afl_utl.h"
#include "stream.h"

#define HAVOC_BLK_SMALL     16
#define HAVOC_BLK_MEDIUM    64
#define HAVOC_BLK_LARGE     256
#define HAVOC_BLK_XL        512

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

static u32 choose_block_len(u32 limit) {

  u32 min_value, max_value;
  u32 rlim = 3;


  switch (UR(rlim)) {

    case 0:  min_value = 1;
             max_value = HAVOC_BLK_SMALL;
             break;

    case 1:  min_value = HAVOC_BLK_SMALL;
             max_value = HAVOC_BLK_MEDIUM;
             break;

    default: 

             if (UR(20)) {

               min_value = HAVOC_BLK_MEDIUM;
               max_value = HAVOC_BLK_LARGE;

             } else {

               min_value = HAVOC_BLK_LARGE;
               max_value = HAVOC_BLK_XL;

             }

  }

  if (min_value >= limit) min_value = 1;

  return min_value + UR(MIN(max_value, limit) - min_value + 1);

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
input_stream* havoc(FuzzState *state,input_stream* stream)

{
  #define HAVOC_STACK 32
  #define HAVOC_TOKEN 20 
  #define ARITH_MAX   35

  s32 len;
  u8 *data;
  input_stream * ret;
  u32 use_stacking = 1 << (1 + UR(7));
  s32 i;

  ret = allocate_enough_space_stream(state,stream->ptr->stream_id,stream->ptr->len);
  memcpy(ret->ptr->data,stream->ptr->data,stream->ptr->len);
  ret->priority = stream->priority;
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
        ((s8*)data)[UR(len)] = interesting_8[UR(sizeof(interesting_8))];
        break;
      }
      case 2:
      {
        if(len < 2)
          break;
        s16* tmp = (s16*)(data + UR(len - 1));

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
        if(len < 4)
          break;
        s32* tmp = (s32*)(data + UR(len - 3));
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
        data[UR(len)] ^= 0xff;
        break;
      }
      case 5:
      {
        data[UR(len)] -= 1 + UR(ARITH_MAX);
        break;
      }
      case 6:
      {
        data[UR(len)] += 1 + UR(ARITH_MAX);
        break;
      }
      case 7:
      {
        if(len < 2)
          break;

        if (UR(2)) {

          u32 pos = UR(len - 1);

          *(u16*)(data + pos) -= 1 + UR(ARITH_MAX);

        } else {

          u32 pos = UR(len - 1);
          u16 num = 1 + UR(ARITH_MAX);

          *(u16*)(data + pos) =
            SWAP16(SWAP16(*(u16*)(data + pos)) - num);

        }
        break;
      }
      case 8:
      {
        if(len < 2)
          break;
        if (UR(2)) {

          u32 pos = UR(len - 1);

          *(u16*)(data + pos) += 1 + UR(ARITH_MAX);

        } else {

          u32 pos = UR(len - 1);
          u16 num = 1 + UR(ARITH_MAX);

          *(u16*)(data + pos) =
            SWAP16(SWAP16(*(u16*)(data + pos)) + num);

        }
        break;
      }
      case 9:
      {
        if(len < 4)
          break;
        if (UR(2)) {

          u32 pos = UR(len - 3);

          *(u32*)(data + pos) -= 1 + UR(ARITH_MAX);

        } else {

          u32 pos = UR(len - 3);
          u32 num = 1 + UR(ARITH_MAX);

          *(u32*)(data + pos) =
            SWAP32(SWAP32(*(u32*)(data + pos)) - num);

        }
        break;
      }
      case 10:
      {
        if(len < 4)
          break;
        if (UR(2)) {

          u32 pos = UR(len - 3);

          *(u32*)(data + pos) += 1 + UR(ARITH_MAX);

        } else {

          u32 pos = UR(len - 3);
          u32 num = 1 + UR(ARITH_MAX);

          *(u32*)(data + pos) =
            SWAP32(SWAP32(*(u32*)(data + pos)) + num);

        }
        break;
      }
      case 11:
      {
        data[UR(len)] ^= 1 + UR(255);
        break;
      }
      case 12:
      {
        if(len < 2)
          break;
        s16* tmp = (s16*)(data + UR(len - 1));
        *tmp = UR(0x10000);
        break;
      }
      case 13:
      {
        if(len < 4)
          break;
        s32* tmp = (s32*)(data + UR(len - 3));
        *tmp = UR(0xffffffff);
        break;
      }
      case 14:
      {
        if(len < 8)
          break;
        s32* tmp1 = (s32*)(data + (UR(len - 7) & 0xfffffffc));
        s32* tmp2 = tmp1 + 1; //(s32*)(data + UR(len - 3));
        s32 val = UR(0xffffffff);
        *tmp1 = val;
        *tmp2 = val;
        break;
      }
        
      case 15:
      {
        if(len < 8)
          break;
        s32* tmp1 = (s32*)(data + (UR(len - 7) & 0xfffffffc));
        s32* tmp2 = tmp1 + 1; //(s32*)(data + UR(len - 3));
        s32 val = 0;
        *tmp1 = val;
        *tmp2 = val;
        break;
      }
      case 16:
      {
        if(len < 8)
          break;
        s32* tmp1 = (s32*)(data + (UR(len - 7) & 0xfffffffc));
        s32* tmp2 = tmp1 + 1; //(s32*)(data + UR(len - 3));
        s32 val = 0xffffffff;
        *tmp1 = val;
        *tmp2 = val;
        break;
      }
      case 17:
      {
        u32 del_from, del_len;
        if (len < 2) break;
        del_len = choose_block_len(len - 1);

        del_from = UR(len - del_len + 1);
        memmove(data + del_from, data + del_from + del_len,
                  len - del_from - del_len);
        ret->ptr->len -= del_len;
        len  -= del_len;
        break;
      }
      case 18:
      {
        if (len + HAVOC_BLK_XL < MAX_FILE) {

          /* Clone bytes (75%) or insert a block of constant bytes (25%). */

          u8  actually_clone = UR(4);
          u32 clone_from, clone_to, clone_len;
          input_stream *new_stream;

          if (actually_clone) {

            clone_len  = choose_block_len(len);
            clone_from = UR(len - clone_len + 1);

          } else {

            clone_len = choose_block_len(HAVOC_BLK_XL);
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
      }
      case 19:
      {
        u32 copy_from, copy_to, copy_len;

        if (len < 2) break;

        copy_len  = choose_block_len(len - 1);

        copy_from = UR(len - copy_len + 1);
        copy_to   = UR(len - copy_len + 1);

        if (UR(4)) {

          if (copy_from != copy_to)
            memmove(ret->ptr->data + copy_to, ret->ptr->data + copy_from, copy_len);

        } else memset(ret->ptr->data + copy_to,
                      UR(2) ? UR(256) : ret->ptr->data[UR(len)], copy_len);
      }
      default:
      break;
    }
    
    
  }
  return ret;
  
}

input_stream* splicing(FuzzState *state,input_stream* stream)
{
  s32 len;
  u8 *data;
  s32 f_diff, l_diff,split_at;
  input_stream * ret;
  input_stream* target;
  vector<input_stream *> *queue_streams;

  
  if(state->all_queued_streams->count(stream->ptr->stream_id) == 0)
  {
    return nullptr;
  }
  queue_streams = (*state->all_queued_streams)[stream->ptr->stream_id];
  if(queue_streams->size() <= 1)
    return nullptr;
  target = (*queue_streams)[UR(queue_streams->size())];
  if(target == stream)
    return nullptr;
  ret = allocate_enough_space_stream(state,stream->ptr->stream_id,stream->ptr->len);
  memcpy(ret->ptr->data,stream->ptr->data,stream->ptr->len);
  ret->priority = stream->priority;
  len = ret->ptr->len;
  data = ret->ptr->data;

  locate_diffs(data, target->ptr->data, MIN(len, target->ptr->len), &f_diff, &l_diff);

  if (f_diff < 0 || l_diff < 2 || f_diff == l_diff) 
  {
    return ret;
  }
  split_at = f_diff + UR(l_diff - f_diff);
  memcpy(data, target->ptr->data, split_at);
  return ret;
}