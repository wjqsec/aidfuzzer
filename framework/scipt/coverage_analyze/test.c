#include <stdint.h>
static __always_inline uint32_t hash_32(uint32_t number)
{
        uint32_t hash_value = number ^ (number >> 16);
        printf("%x\n",hash_value);
        hash_value = hash_value * 0x85ebca6b;
        printf("%x\n",hash_value);
        hash_value = hash_value ^ (hash_value >> 13);
        printf("%x\n",hash_value);
        hash_value = hash_value * 0xc2b2ae35;
        printf("%x\n",hash_value);
        hash_value = hash_value ^ (hash_value >> 16);
        printf("%x\n",hash_value);
        return hash_value;
}



int main()
{
    printf("%x\n", hash_32(0x80003a0) % (1 << 16));
}