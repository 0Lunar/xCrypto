#ifndef XCRYPTO_CIPHER_HEADER_H
#define XCRYPTO_CIPHER_HEADER_H


#include <stdlib.h>
#include <stdint.h>

#define AES_BLOCK_SIZE 16
#define DES_BLOCK_SIZE 8


enum _xcrypto_cipher_modes {
    CIPHER_MODE_NOT_SET,
    CIPHER_MODE_ECB,
    CIPHER_MODE_CBC,
    CIPHER_MODE_CTR,
    CIPHER_MODE_OFB
};

enum _xcrypto_ciphers {
    CIPHER_NOT_SET,
    CIPHER_AES,
    CIPHER_DES
};


enum _xcrypto_cipher_reset_mode {
    CIPHER_FULL_RESET,
    CIPHER_STATE_RESET
};


enum _xcrypto_cipher_op_state {
    CIPHER_SUCCESS,
    CIPHER_ERR_INVALID_ARG,
    CIPHER_ERR_NULL_PTR,
    CIPHER_ERR_UNSUPPORTED_ALGO,
    CIPHER_ERR_INVALID_KEY,
    CIPHER_ERR_UNSUPPORTED_MODE,
    CIPHER_ERR_MEM_ALLOC,
    CIPHER_ERR_MISSING_ALGO,
    CIPHER_ERR_MISSING_BUF,
    CIPHER_ERR_INVALID_BLOCK_SIZE,
    CIPHER_ERR_INVALID_PLAINTEXT_SIZE,
    CIPHER_ERR_INVALID_CIPHERTEXT_SIZE,
    CIPHER_ERR_MISSING_IV,
    CIPHER_ERR_BUFFER_OVERFLOW
};


extern const uint8_t *CipherGetErrorString[];
extern const uint32_t CipherBlockSize[];


struct _xcrypto_generic_cipher {
    enum _xcrypto_ciphers cipher;
    enum _xcrypto_cipher_modes mode;
    enum _xcrypto_cipher_op_state error;
    void *ctx;
    uint8_t *iv;
    uint8_t *tag;
    uint8_t *out;
    size_t ivLen;
    size_t tagLen;
    size_t outLen;
    size_t maxOutLen;
}__attribute__((aligned(16)));


typedef enum _xcrypto_cipher_modes CipherModes;
typedef enum _xcrypto_ciphers Ciphers;
typedef enum _xcrypto_cipher_reset_mode CipherResetMode;
typedef enum _xcrypto_cipher_op_state CipherError;
typedef struct _xcrypto_generic_cipher CipherCtx;


CipherCtx *NewCipher( void );
CipherError CipherSetAlgorithm(CipherCtx *ctx, Ciphers cipher);
CipherError CipherSetKey(CipherCtx *ctx, uint8_t *key, size_t keyLength);
CipherError CipherSetMode(CipherCtx *ctx, CipherModes mode);
CipherError CipherSetIV(CipherCtx *ctx, const uint8_t *iv, size_t ivLen);
CipherError CipherSetBuffer(CipherCtx *ctx, uint8_t *buf, size_t bufSize);
CipherError CipherEncrypt(CipherCtx *ctx, uint8_t *plaintext, size_t plaintextLength);
CipherError CipherDecrypt(CipherCtx *ctx, uint8_t *ciphertext, size_t ciphertextLength);
CipherError CipherFinalize(CipherCtx *ctx);
CipherError FreeCipher(CipherCtx *ctx);
CipherError CipherReset(CipherCtx *ctx, CipherResetMode mode);
CipherError CipherGetError(CipherCtx *ctx);


#endif