#ifndef __xcrypto_des_header__
#define __xcrypto_des_header__


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


void _des_encryptor( struct _xcrypto_des_cipher *cipher, const uint8_t *plaintext );
void _des_decryptor( struct _xcrypto_des_cipher *cipher, const uint8_t *ciphertext );
struct _xcrypto_des_cipher *des_init( const uint8_t *key );
void des_block( struct _xcrypto_des_cipher *cipher, uint8_t *out );


#endif