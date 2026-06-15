#ifndef __xcrypto_hash_header__
#define __xcrypto_hash_header__

#include <stddef.h>
#include <stdint.h>

#define MD5_DIGEST_SIZE 16
#define SHA0_DIGEST_SIZE 20
#define SHA1_DIGEST_SIZE 20


enum _xcrypto_hash_algo {
    XCRYPTO_HASH_NOT_SET,
    XCRYPTO_MD5,
    XCRYPTO_SHA0,
    XCRYPTO_SHA1,
    XCRYPTO_SHA256
};


enum _xcrypto_hash_op_state {
    HASH_SUCCESS,
    HASH_ERR_INVALID_ARG,
    HASH_ERR_NULL_PTR,
    HASH_ERR_UNSUPPORTED_ALGO,
    HASH_ERR_MEM_ALLOC,
    HASH_ERR_MISSING_ALGO,
    HASH_ERR_MISSING_BUF,
    HASH_ERR_BUFFER_OVERFLOW,
    HASH_ERR_ONESHOT
};


enum _xcrypto_hash_reset_mode {
    HASH_STATE_RESET,
    HASH_FULL_RESET
};


struct _xcrypto_hash_ctx {
    enum _xcrypto_hash_algo algorithm;
    enum _xcrypto_hash_op_state error;
    void *ctx;
};


typedef struct _xcrypto_hash_ctx HashCtx;
typedef enum _xcrypto_hash_op_state HashError;
typedef enum _xcrypto_hash_algo HashAlgorithm;
typedef enum _xcrypto_hash_reset_mode HashResetMode;


HashCtx *NewHash();
HashError HashSetAlgorithm(HashCtx *ctx, HashAlgorithm algorithm);
HashError HashUpdate(HashCtx *ctx, const uint8_t *buf, size_t bufSize);
HashError HashFinalize(HashCtx *ctx, uint8_t *buf, size_t bufSize);
HashError HashReset(HashCtx *ctx, HashResetMode mode);
HashError HashOneshot(HashAlgorithm algorithm, const uint8_t *plaintext, size_t plaintextSize, uint8_t *digest, size_t digestSize);


extern const uint8_t *HashGetErrorString[];
extern const size_t HashDigestSize[];

#endif