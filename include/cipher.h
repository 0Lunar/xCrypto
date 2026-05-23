#ifndef __xcrypto_cipher_header__
#define __xcrypto_cipher_header__


#include <stdlib.h>
#include <stdint.h>


enum _cipher_modes {
    ECB,
    CBC,
    CTR,
    OFB
};

enum _ciphers {
    AES,
    DES
};


struct _generic_cipher {
    enum _ciphers cipher;
    enum _cipher_modes mode;
    void *ctx;
    uint8_t *iv;
    uint8_t *tag;
    uint8_t *out;
};


typedef enum _cipher_modes CipherModes;
typedef enum _ciphers Ciphers;
typedef struct _generic_cipher CipherCTX;


CipherCTX *NewCipher(Ciphers cipher, CipherModes mode, const uint8_t *key, size_t keyLength);
uint8_t *CipherPop(CipherCTX *ctx);


#endif