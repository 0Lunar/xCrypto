#ifndef __xcrypto_aes_header__
#define __xcrypto_aes_header__


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


void _aes_encryptor( struct _xcrypto_aes_cipher *cipher, const uint8_t *plaintext );
void _aes_decryptor( struct _xcrypto_aes_cipher *cipher, const uint8_t *ciphertext );
struct _xcrypto_aes_cipher * aes_init( const uint8_t *key, size_t keyLength );


#endif