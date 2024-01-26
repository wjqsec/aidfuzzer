
#include <algorithm>
#include <array>
#include <random>
#include <vector>
#include "xx.h"
#include "iofuzzer.h"
#include "afl_utl.h"
#include "stream.h"


std::vector<char *> dictionary;
#define HAVOC_BLK_SMALL     64
#define HAVOC_BLK_MEDIUM    128
#define HAVOC_BLK_LARGE     2048
#define HAVOC_BLK_XL        (1 << 15)


#define MAX_FILE            (100 * 0x1000)
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


#define INTERESTING_8 \
  -128,          /* Overflow signed 8-bit when decremented  */ \
  -1,            /*                                         */ \
   0,            /*                                         */ \
   1,            /*                                         */ \
   16,           /* One-off with common buffer size         */ \
   32,           /* One-off with common buffer size         */ \
   64,           /* One-off with common buffer size         */ \
   100,          /* One-off with common buffer size         */ \
   127           /* Overflow signed 8-bit when incremented  */

#define INTERESTING_16 \
  -32768,        /* Overflow signed 16-bit when decremented */ \
  -129,          /* Overflow signed 8-bit                   */ \
  0,  /* */ \
   128,          /* Overflow signed 8-bit                   */ \
   255,          /* Overflow unsig 8-bit when incremented   */ \
   256,          /* Overflow unsig 8-bit                    */ \
   512,          /* One-off with common buffer size         */ \
   1000,         /* One-off with common buffer size         */ \
   1024,         /* One-off with common buffer size         */ \
   4096,         /* One-off with common buffer size         */ \
   32767         /* Overflow signed 16-bit when incremented */

#define INTERESTING_32 \
  -2147483648LL, /* Overflow signed 32-bit when decremented */ \
  -100663046,    /* Large negative number (endian-agnostic) */ \
  -32769,        /* Overflow signed 16-bit                  */ \
   0,             \
   32768,        /* Overflow signed 16-bit                  */ \
   65535,        /* Overflow unsig 16-bit when incremented  */ \
   65536,        /* Overflow unsig 16 bit                   */ \
   100663045,    /* Large positive number (endian-agnostic) */ \
   2147483647    /* Overflow signed 32-bit when incremented */


static s8  interesting_8[]  = { INTERESTING_8 };
static s16 interesting_16[] = { INTERESTING_8, INTERESTING_16 };
static s32 interesting_32[] = { INTERESTING_8, INTERESTING_16, INTERESTING_32 };

static u32 choose_block_len(u32 limit,u32 align) {

  u32 ret;
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

             if (UR(5)) {

               min_value = HAVOC_BLK_MEDIUM;
               max_value = HAVOC_BLK_LARGE;

             } else {

               min_value = HAVOC_BLK_LARGE;
               max_value = HAVOC_BLK_XL;

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
    {

      break;
    }
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
    {
      break;
    }
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

inline input_stream* havoc_clone(FuzzState *state,input_stream* stream)
{
  u8 *data = stream->ptr->data;
  s32 len = stream->ptr->len;
  input_stream* ret = stream;
  if (len + len < MAX_FILE) 
  {
    u32 clone_from, clone_to, clone_len;
    input_stream *new_stream;

    clone_len  = choose_block_len(len,stream->ptr->element_size);
    clone_from = UR(len - clone_len + 1);

    clone_to   = UR(len);

    new_stream = allocate_enough_space_stream(state,stream->ptr->stream_id,len+clone_len);

    /* Head */

    memcpy(new_stream->ptr->data, data, clone_to);

    memcpy(new_stream->ptr->data + clone_to, data + clone_from, clone_len);

    /* Tail */
    memcpy(new_stream->ptr->data + clone_to + clone_len, data + clone_to,
            len - clone_to);

    free_stream(state,stream);
    ret = new_stream;
  }
  return ret;
}
inline input_stream* havoc_insert(FuzzState *state,input_stream* stream)
{
  u8 *data = stream->ptr->data;
  s32 len = stream->ptr->len;
  input_stream* ret = stream;
  if (len + HAVOC_BLK_XL < MAX_FILE) {

          u32 clone_from, clone_to, clone_len;
          input_stream *new_stream;

          clone_len = choose_block_len(HAVOC_BLK_XL,stream->ptr->element_size);
          clone_from = 0;


          clone_to   = UR(len);

          new_stream = allocate_enough_space_stream(state,stream->ptr->stream_id,len+clone_len);

          /* Head */

          memcpy(new_stream->ptr->data, data, clone_to);

          /* Inserted part */

          switch(UR(5))
          {
            case 0:
            memset(new_stream->ptr->data + clone_to,0,clone_len);
            break;
            case 1:
            memset(new_stream->ptr->data + clone_to,0xff,clone_len);
            break;
            case 2:
            memset(new_stream->ptr->data + clone_to,UR(0X100),clone_len);
            break;
            case 3:
            // rand_ascii(new_stream->ptr->data + clone_to, clone_len,new_stream->ptr->element_size);
            // break;
            default:
            rand_memset(new_stream->ptr->data + clone_to,clone_len);
            break;
          }
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
  del_len = choose_block_len(len,stream->ptr->element_size);
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
  
  switch(stream->ptr->element_size)
  {
    case 1:
    case 3:
    {
      data[UR(len)] ^= 0xff;
      break;
    }
    case 2:
    {
      s16* tmp = (s16*)(data + (UR(len - 1) & 0xfffffffe));
      *tmp ^= 0xffff;
      break;
    }
    case 4:
    {
      s32* tmp = (s32*)(data + (UR(len - 3) & 0xfffffffc));
      *tmp ^= 0xffffffff;
      break;
    }
    default:
    {
      break;
    }
  }
  return stream;
}
inline input_stream* havoc_random(FuzzState *state,input_stream* stream)
{
  u8 *data = stream->ptr->data;
  s32 len = stream->ptr->len;
  switch(stream->ptr->element_size)
  {
    case 1:
    case 3:
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
    case 3:
    {
      data[UR(len)] = 0x20 + UR(0x80 - 0x20);
      break;
    }
    case 2:
    {
      s16* tmp = (s16*)(data + (UR(len - 1) & 0xfffffffe));
      *tmp = 0x20 + UR(0x80 - 0x20);
      break;
    }
    
    case 4:
    {
      s32* tmp = (s32*)(data + (UR(len - 3) & 0xfffffffc));
      *tmp = 0x20 + UR(0x80 - 0x20);
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

  if (copy_from != copy_to)
    memmove(data + copy_to, data + copy_from, copy_len);
  return stream;      
}
inline input_stream* havoc_state_value(FuzzState *state,input_stream* stream)
{
  u8 *data = stream->ptr->data;
  s32 len = stream->ptr->len;
  switch(stream->ptr->element_size)
  {
    case 1:
    case 3:
    {
      data[UR(len)] = -10 + UR(21);
      break;
    }
    case 2:
    {
      s16* tmp = (s16*)(data + (UR(len - 1) & 0xfffffffe));
      *tmp = -10 + UR(21);
      break;
    }
    
    case 4:
    {
      s32* tmp = (s32*)(data + (UR(len - 3) & 0xfffffffc));
      *tmp = -10 + UR(21);
      break;
    }
    default:
    {
      break;
    }
  }
  return stream;
}
inline input_stream* havoc_shuffle(FuzzState *state,input_stream* stream)
{
  u8 *data = stream->ptr->data;
  s32 len = stream->ptr->len;

  int i,j;
  for (i = len - 1; i > 0; --i) 
  {
        j = UR(i + 1);
        u8 temp = data[i];
        data[i] = data[j];
        data[j] = temp;
  }
  return stream;

}
inline input_stream* havoc_dictionary(FuzzState *state,input_stream* stream)
{
  if(dictionary.size() == 0)
    return stream;
  u8 *data = stream->ptr->data;
  s32 len = stream->ptr->len;

  int select_dic = UR(dictionary.size());
  char *select_str = dictionary[select_dic];
  int dic_str_len = strlen(select_str) + 1; // null end
  

  switch(stream->ptr->element_size)
  {
    case 1:
    {
      int pos = UR(len);
      if(dic_str_len > (len - pos))
        break;
      memcpy(data + pos, select_str, dic_str_len);
      break;
    }
    case 2:
    {
      int pos = UR(len - 1) & 0xfffffffe;
      if(dic_str_len > ((len - pos) >> 1))
        break;
      s16* tmp = (s16*)(data + pos);
      for(int j = 0 ; j < dic_str_len ; j++)
      {
        tmp[j] = select_str[j];
      }
      break;
    }
    case 3:
    {
      break;
    }
    case 4:
    {
      int pos = UR(len - 3) & 0xfffffffc;
      if(dic_str_len > ((len - pos) >> 2))
        break;
      s32* tmp = (s32*)(data + pos);
      for(int j = 0 ; j < dic_str_len ; j++)
      {
        tmp[j] = select_str[j];
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


typedef input_stream* (*havoc_fuc) (FuzzState *state,input_stream* stream);

static havoc_fuc havoc_arrays[] = { 
                                    havoc_flip_bit, 
                                    havoc_interesting_value, 
                                    havoc_insert,
                                    havoc_clone,
                                    havoc_delete,
                                    havoc_revert,
                                    havoc_random,
                                    havoc_ascii,
                                    havoc_splicing_copy,
                                    havoc_state_value,
                                    havoc_shuffle,
                                    havoc_dictionary
                                    };

input_stream* havoc(FuzzState *state,input_stream* stream)
{
  input_stream * ret;
  u32 use_stacking;
  s32 i;
  

  ret = resize_stream(state,stream,stream->ptr->len);

  // use_stacking = 1;(1 << (1 + UR(3)));

  // for (i = 0; i < use_stacking; i++) 
  {

    int index = UR(sizeof(havoc_arrays) / sizeof(havoc_arrays[0]));
    

    ret = havoc_arrays[index](state,ret);

  }

  return ret;
  
}

void add_random(FuzzState *state, queue_entry *q)
{
  input_stream * new_stream;
  int elements = 1 << UR(6);
  // int elements = 1000;
  int len;

  map<u32,input_stream *> new_streams;


  for(auto it = q->streams->begin(); it != q->streams->end(); it++)
  {
    if (stream_shouldnot_mutate(it->second))
      continue;
    len = elements * it->second->ptr->element_size;

    new_stream = resize_stream(state,it->second,it->second->ptr->len + len);


    switch(UR(5))
    {
      case 0:
      memset(new_stream->ptr->data + it->second->ptr->len,0,len);
      break;
      case 1:
      memset(new_stream->ptr->data + it->second->ptr->len,0xff,len);
      break;
      case 2:
      memset(new_stream->ptr->data + it->second->ptr->len,UR(0X100),len);
      break;
      case 3:
      // rand_ascii(new_stream->ptr->data + it->second->ptr->len, len,new_stream->ptr->element_size);
      // break;
      default:
      rand_memset(new_stream->ptr->data + it->second->ptr->len,len);
      break;
    }
    
    new_streams[it->second->ptr->stream_id] = new_stream;
    
  }
  for(auto it = new_streams.begin(); it != new_streams.end(); it++)
  {
    replace_stream(state,q,it->first,it->second);
  }
}

 
    

// }



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