#ifndef __xcrypto_aes_header__
#define __xcrypto_aes_header__


#include <stdio.h>
#include <stdint.h>


#define AES_BLOCK_SIZE 16
#define AES_BLOCK_SIZE_BITS 128
#define IS_LITTLE_ENDIAN() ((*(uint8_t*)&(uint16_t){1}) == 1)


struct aes_cipher;


struct aes_cipher * aes_init( const uint8_t *key, size_t keyLength );
void free_aes( struct aes_cipher *cipher, bool dynamic );
void _aes_encryptor( struct aes_cipher *cipher, const uint8_t *plaintext );
void _aes_decryptor( struct aes_cipher *cipher, const uint8_t *ciphertext );


extern const uint8_t _aes_sbox[];
extern const uint8_t _aes_rsbox[];


typedef struct aes_cipher AesCipher;


#endif