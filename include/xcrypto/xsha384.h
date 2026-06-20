#ifndef XCRYPTO_SHA384_HEADER_H
#define XCRYPTO_SHA384_HEADER_H

#include <stdint.h>
#include <stddef.h>


enum _xcrypto_sha384_errors {
    SHA384_SUCCESS,
    SHA384_ERR_INVALID_ARG,
    SHA384_ERR_NULL_PTR,
    SHA384_ERR_MEM_ALLOC,
};


struct _xcrypto_sha384_ctx {
    uint64_t H0;
    uint64_t H1;
    uint64_t H2;
    uint64_t H3;
    uint64_t H4;
    uint64_t H5;
    uint64_t H6;
    uint64_t H7;

    uint64_t hi_bits;
    uint64_t lo_bits;

    uint8_t buf[128];
    size_t buf_len;

    enum _xcrypto_sha384_errors error;
};


typedef enum _xcrypto_sha384_errors XSHA384_ERRORS;
typedef struct _xcrypto_sha384_ctx XSHA384_CTX;

XSHA384_CTX *XSHA384_Init();
XSHA384_ERRORS XSHA384_Update(XSHA384_CTX *ctx, const uint8_t *buf, size_t bufSize);
XSHA384_ERRORS XSHA384_Finalize(XSHA384_CTX *ctx, uint8_t *buf);
XSHA384_ERRORS XSHA384_Reset(XSHA384_CTX *ctx);

#endif