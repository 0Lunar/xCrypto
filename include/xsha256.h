#ifndef __xcrypto_xsha256_header__
#define __xcrypto_xsha256_header__

#include <stdint.h>
#include <stddef.h>


enum _xcrypto_sha256_errors {
    SHA256_SUCCESS,
    SHA256_ERR_INVALID_ARG,
    SHA256_ERR_NULL_PTR,
    SHA256_ERR_MEM_ALLOC,
};


struct _xcrypto_sha256_ctx {
    uint32_t H0;
    uint32_t H1;
    uint32_t H2;
    uint32_t H3;
    uint32_t H4;
    uint32_t H5;
    uint32_t H6;
    uint32_t H7;

    uint64_t bits;

    uint8_t buf[64];
    size_t buf_len;

    enum _xcrypto_sha256_errors error;
};


typedef enum _xcrypto_sha256_errors XSHA256_ERRORS;
typedef struct _xcrypto_sha256_ctx XSHA256_CTX;

XSHA256_CTX *XSHA256_Init();
XSHA256_ERRORS XSHA256_Update(XSHA256_CTX *ctx, const uint8_t *buf, size_t bufSize);
XSHA256_ERRORS XSHA256_Finalize(XSHA256_CTX *ctx, uint8_t *buf);

#endif