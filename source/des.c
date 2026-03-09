#include "des.h"


struct des_cipher
{
    uint64_t block;
    uint8_t key[8];
    uint8_t subkeys[16][8];
};



static void initialPermutation(struct des_cipher *cipher) {
    uint64_t block = cipher->block;
    uint32_t left, right;
    uint32_t temp;

    left =  (block >> 32) & 0xFFFFFFFF;
    right = block & 0xFFFFFFFF;

    PERM_OP(right, left,  temp, 4, 0x0f0f0f0f);
    PERM_OP(left,  right, temp, 16, 0x0000ffff);
    PERM_OP(right, left,  temp, 2, 0x33333333);
    PERM_OP(left,  right, temp, 8, 0x00ff00ff);
    PERM_OP(right, left,  temp, 1, 0x55555555);

    cipher->block = ((uint64_t)(right)) << 32 | left;
}