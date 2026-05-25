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


void _des_encryptor( struct des_cipher *cipher, const uint8_t *plaintext );
void _des_decryptor( struct des_cipher *cipher, const uint8_t *ciphertext );
struct des_cipher *des_init( const uint8_t *key );
void des_block( struct des_cipher *cipher, uint8_t *out );


#endif