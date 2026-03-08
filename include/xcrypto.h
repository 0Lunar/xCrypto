#ifndef __xcrypto_header__
#define __xcrypto_header__

#include <stdint.h>
#include <stdbool.h>


#define AES_BLOCK_SIZE 16
#define AES_BLOCK_SIZE_BITS 128
#define DES_BLOCK_SIZE 8
#define DES_BLOCK_SIZE_BITS 64
#define IS_LITTLE_ENDIAN() ((*(uint8_t*)&(uint16_t){1}) == 1)  


enum _cipher_modes {
    ECB
};

enum _ciphers {
    AES
};


// Advanced Encryption Standard (AES)

struct aes_cipher * aes_init(const unsigned char *key, size_t keyLength);
void free_aes(struct aes_cipher *cipher, bool dynamic);
void aes_encrypt(struct aes_cipher *cipher, const uint8_t *plaintext, const size_t plaintextLenght, uint8_t *ciphertext);
void aes_decrypt(struct aes_cipher *cipher, const uint8_t *ciphertext, const size_t ciphertextLength, uint8_t *plaintext);


struct aes_cipher;
extern const unsigned char _aes_sbox[];
extern const unsigned char _aes_rsbox[];
const uint8_t _des_ip_table[];


typedef enum _cipher_modes CipherModes;
typedef enum _ciphers Ciphers;
typedef enum _log_level LogLevel;
typedef struct aes_cipher AesCipher;

#endif