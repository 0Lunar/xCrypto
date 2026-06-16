#ifndef __xcrypto_xsha512_header__
#define __xcrypto_xsha512_header__

#include <stdint.h>
#include <stddef.h>


enum _xcrypto_sha512_errors {
    SHA512_SUCCESS,
    SHA512_ERR_INVALID_ARG,
    SHA512_ERR_NULL_PTR,
    SHA512_ERR_MEM_ALLOC,
};


struct _xcrypto_sha512_ctx {
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

    enum _xcrypto_sha512_errors error;
};


typedef enum _xcrypto_sha512_errors XSHA512_ERRORS;
typedef struct _xcrypto_sha512_ctx XSHA512_CTX;

XSHA512_CTX *XSHA512_Init();
XSHA512_ERRORS XSHA512_Update(XSHA512_CTX *ctx, const uint8_t *buf, size_t bufSize);
XSHA512_ERRORS XSHA512_Finalize(XSHA512_CTX *ctx, uint8_t *buf);
XSHA512_ERRORS XSHA512_Reset(XSHA512_CTX *ctx);

#endif