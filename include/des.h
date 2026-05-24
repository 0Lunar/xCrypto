#ifndef __xcrypto_des_header__
#define __xcrypto_des_header__


#define DES_BLOCK_SIZE 8
#define DES_BLOCK_SIZE_BITS 64
#define DES_ROUNDS 16


#include <stdio.h>
#include <stdint.h>


struct des_cipher
{
    uint64_t block;
    uint64_t key;
    uint64_t subkeys[16];
};


typedef struct des_cipher DesCipher;


#endif