#ifndef XCRYPTO_DES_HEADER_H
#define XCRYPTO_DES_HEADER_H


#define DES_BLOCK_SIZE 8
#define DES_BLOCK_SIZE_BITS 64
#define DES_ROUNDS 16


#include <stddef.h>
#include <stdint.h>


struct _xcrypto_des_cipher
{
    uint64_t block;
    uint64_t key;
    uint64_t subkeys[16];
};


typedef struct _xcrypto_des_cipher DesCipher;


void DesEncryptor( DesCipher *cipher, const uint8_t *plaintext );
void DesDecryptor( DesCipher *cipher, const uint8_t *ciphertext );
DesCipher *DesInit( const uint8_t *key );
void DesGetBlock( struct _xcrypto_des_cipher *cipher, uint8_t *out );


#endif