#ifndef XCRYPTO_AES_HEADER_H
#define XCRYPTO_AES_HEADER_H


#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>


#define AES_BLOCK_SIZE 16
#define AES_BLOCK_SIZE_BITS 128

struct _xcrypto_aes_cipher {
    size_t key_size;
    uint8_t *key;
    uint8_t state[16];
    uint8_t roundKey[15][16];
} __attribute__((aligned(16)));


typedef struct _xcrypto_aes_cipher AesCipher;


void AesEncryptor( AesCipher *cipher, const uint8_t *plaintext );
void AesDecryptor( AesCipher *cipher, const uint8_t *ciphertext );
AesCipher * AesInit( const uint8_t *key, size_t keyLength );
void AesFree( AesCipher *cipher );
void AesGetBlock( AesCipher *cipher, uint8_t *buf );


#endif