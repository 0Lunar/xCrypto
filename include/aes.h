#ifndef __xcrypto_aes_header__
#define __xcrypto_aes_header__


#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>


#define AES_BLOCK_SIZE 16
#define AES_BLOCK_SIZE_BITS 128

struct aes_cipher {
    size_t key_size;
    uint8_t *key;
    uint8_t state[16];
    uint8_t roundKey[15][16];
} __attribute__((aligned(16)));


typedef struct aes_cipher AesCipher;


#endif