#ifndef __xcrypto_xsha224_header__
#define __xcrypto_xsha224_header__

#include <stdint.h>
#include <stddef.h>


enum _xcrypto_sha224_errors {
    SHA224_SUCCESS,
    SHA224_ERR_INVALID_ARG,
    SHA224_ERR_NULL_PTR,
    SHA224_ERR_MEM_ALLOC,
};


struct _xcrypto_sha224_ctx {
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

    enum _xcrypto_sha224_errors error;
};


typedef enum _xcrypto_sha224_errors XSHA224_ERRORS;
typedef struct _xcrypto_sha224_ctx XSHA224_CTX;

XSHA224_CTX *XSHA224_Init();
XSHA224_ERRORS XSHA224_Update(XSHA224_CTX *ctx, const uint8_t *buf, size_t bufSize);
XSHA224_ERRORS XSHA224_Finalize(XSHA224_CTX *ctx, uint8_t *buf);
XSHA224_ERRORS XSHA224_Reset(XSHA224_CTX *ctx);


#endif