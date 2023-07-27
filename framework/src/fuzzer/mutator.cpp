
#include "xx.h"
#include "iofuzzer.h"
#include "afl_utl.h"


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
  u32 rlim = MIN(queue_cycle, 3);

  if (!run_over10m) rlim = 1;

  switch (UR(rlim)) {

    case 0:  min_value = 1;
             max_value = HAVOC_BLK_SMALL;
             break;

    case 1:  min_value = HAVOC_BLK_SMALL;
             max_value = HAVOC_BLK_MEDIUM;
             break;

    default: 

             if (UR(10)) {

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
void havoc(FuzzState *state,input_stream* stream)

{
  #define HAVOC_STACK 32
  #define HAVOC_TOKEN 20 
  #define ARITH_MAX   35

  u32 use_stacking = 1 << (1 + UR(7));
  s32 len = stream->ptr->len;
 
  u32 mode = stream->ptr->mode;
  u8 *data = stream->ptr->data;
  s32 i;
  
  if(mode == MODEL_PASSTHROUGH || mode == MODEL_CONSTANT)
    return;

  if(mode == MODEL_VALUE_SET)
  {
    u32 *value_set_len_ptr = (u32 *)stream->ptr->data;
    len -= sizeof(*value_set_len_ptr) + (*value_set_len_ptr) * sizeof(u32);
    data += sizeof(*value_set_len_ptr) + (*value_set_len_ptr) * sizeof(u32);
    for (i = 0; i < use_stacking; i++)
      data[UR(len)] = UR(*value_set_len_ptr);
    return;      
  }
  
  if(mode == MODEL_BIT_EXTRACT && stream->ptr->element_size == 1 && UR(5))
  {
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
          data[UR(len)] ^= 0xff;
          break;
        }
        case 3:
        {
          data[UR(len)] -= 1 + UR(ARITH_MAX);
          break;
        }
        case 4:
        {
          data[UR(len)] += 1 + UR(ARITH_MAX);
          break;
        }
        case 5:
          data[UR(len)] ^= UR(0x100);
          break;
        case 6:
        case 7:
        case 8:
        case 9:
        case 10:
        case 11:
        case 12:
        case 13:
        case 14:
        case 15:
        case 16:
        case 18:
        case 19:
        default:
        {
          data[UR(len)] = 0x61 + UR(0x7a - 0x60);  // ascii printable 
        }
      }
    }
    return;
  }
  
  for (i = 0; i < use_stacking; i++) 
  {
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
        case 18:
        case 19:
        {
          FLIP_BIT(data,UR(len << 3));
        }
        default:
        break;
      }
    }
    
  }
  
}