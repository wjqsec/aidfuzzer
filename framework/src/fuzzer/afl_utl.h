#ifndef AFLUTL_INCLUDED
#define AFLUTL_INCLUDED
#include <sys/time.h>
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include "fuzzer.h"



#define FF(_b)  (0xff << ((_b) << 3))
#define FF_WORD(_b)  ((u64)0xffff << ((_b) << 4))

static u8 count_class_lookup8[256];

static u16 count_class_lookup16[65536];

inline static void classify_counts(u64* mem, u32 size) {

  u32 i = size >> 3;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) {

      u16* mem16 = (u16*)mem;

      mem16[0] = count_class_lookup16[mem16[0]];
      mem16[1] = count_class_lookup16[mem16[1]];
      mem16[2] = count_class_lookup16[mem16[2]];
      mem16[3] = count_class_lookup16[mem16[3]];

    }
    mem++;

  }
}
inline static int has_new_bits(u8* virgin_map, u8 *trace_bits, u32 size)
{
  u64* current = (u64*)trace_bits;
  u64* virgin  = (u64*)virgin_map;

  u32  i = (size >> 3);

  while (i--) 
  {
    if (unlikely(*current) && unlikely(*current & *virgin)) 
    {
      return 1;
    }
    current++;
    virgin++;
  }
  return 0;
}
inline static void get_new_bits(u8* virgin_map, u8 *trace_bits, u32 size, u8* out)
{
  u64 *ret = (u64 *)out;
  u64* current = (u64*)trace_bits;
  u64* virgin  = (u64*)virgin_map;

  u32  j = (size >> 3);
  for(u32 i = 0 ; i < j ; i++)
  {
    ret[i] = (current[i] & virgin[i]);
  }
}
inline static bool a_contains_b(u8* a, u8* b, u32 size)
{
  u64* aa = (u64*)a;
  u64* bb  = (u64*)b;
  u32  j = (size >> 3);
  for(u32 i = 0 ; i < j ; i++)
  {
    if((aa[i] | bb[i]) != aa[i])
      return false;
  }
  return true;
}
inline static void update_virgin(u8* virgin_map, u8 *trace_bits, u32 size) 
{
  u64* current = (u64*)trace_bits;
  u64* virgin  = (u64*)virgin_map;

  u32  i = (size >> 3);


  while (i--) {

    if (unlikely(*current) && unlikely(*current & *virgin)) {

      // if (likely(ret < 2)) {

      //   u8* cur = (u8*)current;
      //   u8* vir = (u8*)virgin;

      //   if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
      //       (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff) ||
      //       (cur[4] && vir[4] == 0xff) || (cur[5] && vir[5] == 0xff) ||
      //       (cur[6] && vir[6] == 0xff) || (cur[7] && vir[7] == 0xff)) ret = 2;
      //   else ret = 1;

      // }

      *virgin &= ~*current;

    }

    current++;
    virgin++;

  }
}
#ifdef TWOBYTES_COVERAGE
inline static void init_count_class16(void) {
  int i;
  count_class_lookup16[0] = 0;
  for(i = 1;i <= 1; i++)
    count_class_lookup16[i] = 1 << 0;
  for(i = 2;i <= 2; i++)
    count_class_lookup16[i] = 1 << 1;
  for(i = 3;i <= 3; i++)
    count_class_lookup16[i] = 1 << 2;
  for(i = 4;i <= 7; i++)
    count_class_lookup16[i] = 1 << 3;
  for(i = 8;i <= 15; i++)
    count_class_lookup16[i] = 1 << 4;
  for(i = 16;i <= 31; i++)
    count_class_lookup16[i] = 1 << 5;
  for(i = 32;i <= 63; i++)
    count_class_lookup16[i] = 1 << 6;
  for(i = 64;i <= 127; i++)
    count_class_lookup16[i] = 1 << 7;
  for(i = 128;i <= 191; i++)
    count_class_lookup16[i] = 1 << 8;
  for(i = 192;i <= 255; i++)
    count_class_lookup16[i] = 1 << 9;
  for(i = 256;i <= 319; i++)
    count_class_lookup16[i] = 1 << 10;
  for(i = 320;i <= 383; i++)
    count_class_lookup16[i] = 1 << 11;
  for(i = 384;i <= 447; i++)
    count_class_lookup16[i] = 1 << 12;
  for(i = 448;i <= 511; i++)
    count_class_lookup16[i] = 1 << 13;
  for(i = 512;i <= 575; i++)
    count_class_lookup16[i] = 1 << 14;
  for(i = 576;i <= 65535; i++)
    count_class_lookup16[i] = 1 << 15;

  // for(i = 64;i <= 95; i++)
  //   count_class_lookup16[i] = 1 << 7;
  // for(i = 96;i <= 127; i++)
  //   count_class_lookup16[i] = 1 << 8;
  // for(i = 128;i <= 159; i++)
  //   count_class_lookup16[i] = 1 << 9;
  // for(i = 160;i <= 191; i++)
  //   count_class_lookup16[i] = 1 << 10;
  // for(i = 192;i <= 223; i++)
  //   count_class_lookup16[i] = 1 << 11;
  // for(i = 224;i <= 255; i++)
  //   count_class_lookup16[i] = 1 << 12;
  // for(i = 256;i <= 287; i++)
  //   count_class_lookup16[i] = 1 << 13;
  // for(i = 288;i <= 319; i++)
  //   count_class_lookup16[i] = 1 << 14;
  // for(i = 320;i <= 65535; i++)
  //   count_class_lookup16[i] = 1 << 15;

}
inline static u32 count_trace_covered_bbl(u8* mem, u32 size) {


  u64* ptr = (u64*)mem;
  u32  i   = (size >> 3);
  u32  ret = 0;

  while (i--) {

    u64 v = *(ptr++);

    if (!v) continue;
    if (v & FF_WORD(0)) ret++;
    if (v & FF_WORD(1)) ret++;
    if (v & FF_WORD(2)) ret++;
    if (v & FF_WORD(3)) ret++;

  }

  return ret;
}
inline static u32 count_covered_bbl(u8* mem, u32 size) {

  u64* ptr = (u64*)mem;
  u32  i   = (size >> 3);
  u32  ret = 0;

  while (i--) {

    u64 v = *(ptr++);

    /* This is called on the virgin bitmap, so optimize for the most likely
       case. */

    if (v == 0xffffffffffffffff) continue;
    if ((v & FF_WORD(0)) != FF_WORD(0)) ret++;
    if ((v & FF_WORD(1)) != FF_WORD(1)) ret++;
    if ((v & FF_WORD(2)) != FF_WORD(2)) ret++;
    if ((v & FF_WORD(3)) != FF_WORD(3)) ret++;

  }

  return ret;

}
#endif

#ifdef ONEBYTE_COVERAGE
inline static void init_count_class16(void) {
  count_class_lookup8[0] = 0;
  count_class_lookup8[1] = 1;
  count_class_lookup8[2] = 2;
  count_class_lookup8[3] = 4;
  int i;
  
  for(i = 4;i <= 7; i++)
    count_class_lookup8[i] = 8;
  for(i = 8;i <= 15; i++)
    count_class_lookup8[i] = 16;
  for(i = 16;i <= 31; i++)
    count_class_lookup8[i] = 32;
  for(i = 32;i <= 127; i++)
    count_class_lookup8[i] = 64;
  for(i = 128;i <= 255; i++)
    count_class_lookup8[i] = 128;
  

  u32 b1, b2;

  for (b1 = 0; b1 < 256; b1++) 
    for (b2 = 0; b2 < 256; b2++)
      count_class_lookup16[(b1 << 8) + b2] = 
        (count_class_lookup8[b1] << 8) |
        count_class_lookup8[b2];

}

// inline static u32 count_bits(u8* mem, u32 size) {

//   u32* ptr = (u32*)mem;
//   u32  i   = (size >> 2);
//   u32  ret = 0;

//   while (i--) {

//     u32 v = *(ptr++);

//     if (v == 0xffffffff) {
//       ret += 32;
//       continue;
//     }

//     v -= ((v >> 1) & 0x55555555);
//     v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
//     ret += (((v + (v >> 4)) & 0xF0F0F0F) * 0x01010101) >> 24;

//   }

//   return ret;

// }
inline static u32 count_trace_covered_bbl(u8* mem, u32 size) {


  u32* ptr = (u32*)mem;
  u32  i   = (size >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    if (!v) continue;
    if (v & FF(0)) ret++;
    if (v & FF(1)) ret++;
    if (v & FF(2)) ret++;
    if (v & FF(3)) ret++;

  }

  return ret;
}

inline static u32 count_covered_bbl(u8* mem, u32 size) {

  u32* ptr = (u32*)mem;
  u32  i   = (size >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    /* This is called on the virgin bitmap, so optimize for the most likely
       case. */

    if (v == 0xffffffff) continue;
    if ((v & FF(0)) != FF(0)) ret++;
    if ((v & FF(1)) != FF(1)) ret++;
    if ((v & FF(2)) != FF(2)) ret++;
    if ((v & FF(3)) != FF(3)) ret++;

  }

  return ret;

}
#endif


inline static u32 hash32(const void* key, u32 len) 
{
#define HASH_CONST          0xa5b35705
#define ROL64(_x, _r)  ((((u64)(_x)) << (_r)) | (((u64)(_x)) >> (64 - (_r))))
  const u64* data = (u64*)key;
  u64 h1 = HASH_CONST ^ len;

  len >>= 3;

  while (len--) {

    u64 k1 = *data++;

    k1 *= 0x87c37b91114253d5ULL;
    k1  = ROL64(k1, 31);
    k1 *= 0x4cf5ad432745937fULL;

    h1 ^= k1;
    h1  = ROL64(h1, 27);
    h1  = h1 * 5 + 0x52dce729;

  }

  h1 ^= h1 >> 33;
  h1 *= 0xff51afd7ed558ccdULL;
  h1 ^= h1 >> 33;
  h1 *= 0xc4ceb9fe1a85ec53ULL;
  h1 ^= h1 >> 33;

  return h1;
}


inline static u32 UR(u32 limit) {

  #define RESEED_RNG          10000
  static u32 rand_cnt = 0;
  if (unlikely(!rand_cnt--)) {

    u32 seed[2];

    FILE *f = fopen("/dev/urandom","rb");
    if(!f)
    {
        printf("open random file error\n");
        exit(0);
    }
    fread(seed,sizeof(seed),1,f);
    fclose(f);
    srandom(seed[0]);
    rand_cnt = (RESEED_RNG / 2) + (seed[1] % RESEED_RNG);
  }

  return random() % limit;

}

inline void rand_memset(void* ptr, int len)
{
  u32 *tmp1 = (u32*)ptr;
  u8 *tmp2;
  int size_in_dword = len / 4;
  int size_remain = len - (size_in_dword * 4);

  tmp2 = (u8 *)ptr + (size_in_dword * 4);
  for(int i = 0; i < size_in_dword; i++)
  {
    tmp1[i] = UR(0xffffffff);
  }
  for(int i = 0 ; i < size_remain ; i++)
  {
    tmp2[i] = UR(0xff);
  }
}

#endif