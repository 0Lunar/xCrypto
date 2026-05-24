#ifndef __xcrypto_cipher_header__
#define __xcrypto_cipher_header__


#include <stdlib.h>
#include <stdint.h>


enum _cipher_modes {
    CIPHER_MODE_NOT_SET,
    ECB,
    CBC,
    CTR,
    OFB
};

enum _ciphers {
    CIPHER_NOT_SET,
    AES,
    DES
};


enum _cipher_reset_mode {
    CIPHER_FULL_RESET,
    CIPHER_STATE_RESET
};


enum _cipher_op_state {
    CIPHER_SUCCESS,
    CIPHER_ERR_INVALID_ARG,
    CIPHER_ERR_NULL_PTR,
    CIPHER_ERR_UNSUPPORTED_ALGO,
    CIPHER_ERR_INVALID_KEY,
    CIPHER_ERR_UNSUPPORTED_MODE,
    CIPHER_ERR_MEM_ALLOC,
    CIPHER_ERR_MISSING_ALGO,
    CIPHER_ERR_INVALID_BLOCK_SIZE,
    CIPHER_ERR_INVALID_PLAINTEXT_SIZE,
    CIPHER_ERR_INVALID_CIPHERTEXT_SIZE
};


struct _generic_cipher {
    enum _ciphers cipher;
    enum _cipher_modes mode;
    enum _cipher_op_state error;
    void *ctx;
    uint8_t *iv;
    uint8_t *tag;
    uint8_t *out;
    size_t outLen;
};


typedef enum _cipher_modes CipherModes;
typedef enum _ciphers Ciphers;
typedef enum _cipher_reset_mode CipherResetMode;
typedef enum _cipher_op_state CipherError;
typedef struct _generic_cipher CipherCtx;


CipherCtx *NewCipher( void );
CipherError CipherSetAlgorithm(CipherCtx *ctx, Ciphers cipher);
CipherError CipherSetKey(CipherCtx *ctx, uint8_t *key, size_t keyLength);
CipherError CipherSetMode(CipherCtx *ctx, CipherModes mode);
CipherError CipherSetIV(CipherCtx *ctx, const uint8_t *iv);
CipherError CipherEncrypt(CipherCtx *ctx, uint8_t *plaintext, size_t plaintextLength);
CipherError CipherDecrypt(CipherCtx *ctx, uint8_t *ciphertext, size_t ciphertextLength);
uint8_t *CipherFinalize(CipherCtx *ctx);
CipherError FreeCiphertext(CipherCtx *ctx);
CipherError CipherReset(CipherCtx *ctx, CipherResetMode mode);
CipherError GetError(CipherCtx *ctx);

extern const char *GetErrorString[];


#endif