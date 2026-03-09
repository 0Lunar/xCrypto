#ifndef __xcrypto_aes_header__
#define __xcrypto_aes_header__


#include <stdio.h>
#include <stdint.h>


#define AES_BLOCK_SIZE 16
#define AES_BLOCK_SIZE_BITS 128


struct aes_cipher;


struct aes_cipher * aes_init(const unsigned char *key, size_t keyLength);
void free_aes(struct aes_cipher *cipher, bool dynamic);
void aes_encrypt(struct aes_cipher *cipher, const uint8_t *plaintext, const size_t plaintextLenght, uint8_t *ciphertext);
void aes_decrypt(struct aes_cipher *cipher, const uint8_t *ciphertext, const size_t ciphertextLength, uint8_t *plaintext);


extern const uint8_t _aes_sbox[];
extern const uint8_t _aes_rsbox[];


typedef struct aes_cipher AesCipher;


#endif