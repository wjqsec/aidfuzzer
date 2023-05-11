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

#define HASH_CONST          0xa5b35705
static s8  interesting_8[]  = { INTERESTING_8 };
static s16 interesting_16[] = { INTERESTING_8, INTERESTING_16 };
static s32 interesting_32[] = { INTERESTING_8, INTERESTING_16, INTERESTING_32 };
static u8 count_class_lookup8[256];

static u16 count_class_lookup16[65536];

void init_count_class16(void) {
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
inline static u8 has_new_bits_update_virgin(u8* virgin_map, u8 *trace_bits, u32 size) 
{
  u64* current = (u64*)trace_bits;
  u64* virgin  = (u64*)virgin_map;

  u32  i = (size >> 3);

  u8   ret = 0;

  while (i--) {

    if (unlikely(*current) && unlikely(*current & *virgin)) {

      if (likely(ret < 2)) {

        u8* cur = (u8*)current;
        u8* vir = (u8*)virgin;

        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff) ||
            (cur[4] && vir[4] == 0xff) || (cur[5] && vir[5] == 0xff) ||
            (cur[6] && vir[6] == 0xff) || (cur[7] && vir[7] == 0xff)) ret = 2;
        else ret = 1;

      }

      *virgin &= ~*current;

    }

    current++;
    virgin++;

  }

  return ret;

}
inline static u32 count_bits(u8* mem, u32 size) {

  u32* ptr = (u32*)mem;
  u32  i   = (size >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    if (v == 0xffffffff) {
      ret += 32;
      continue;
    }

    v -= ((v >> 1) & 0x55555555);
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
    ret += (((v + (v >> 4)) & 0xF0F0F0F) * 0x01010101) >> 24;

  }

  return ret;

}
inline static u32 count_bytes(u8* mem, u32 size) {

#define FF(_b)  (0xff << ((_b) << 3))
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
inline static u32 count_non_255_bytes(u8* mem, u32 size) {

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
static __always_inline uint64_t hash_64(uint64_t val, unsigned int bits)
{
#define GOLDEN_RATIO_64 0x61C8864680B583EBull
        return val * GOLDEN_RATIO_64 >> (64 - bits);
}
#define ROL64(_x, _r)  ((((u64)(_x)) << (_r)) | (((u64)(_x)) >> (64 - (_r))))
inline static u32 hash32(const void* key, u32 len) 
{

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

inline static void minimize_bits(u8* dst, u8* src, u32 size) {

  u32 i = 0;

  while (i < size) {

    if (*(src++)) dst[i >> 3] |= 1 << (i & 7);
    i++;
  }

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

// does d2 totally cover d1?
inline static bool cover_all_bits(u8* d1, u8* d2, u32 size)
{
  u32* s1 = (u32*)d1;
  u32* s2  = (u32*)d2;
  u32 j = size >> 2;
  for(u32 i = 0; i < j ; i++ )
  {
    if((s1[i] | s2[i]) != s2[i])
    {
      //printf("return false %d  %x  %x  %x  %d\n",i,s1[i],s2[i],s1[i] | s2[i],(s1[i] | s2[i]) != s2[i]);
      return false;
    }
  }
  return true;
}


