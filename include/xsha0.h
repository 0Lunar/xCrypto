#ifndef __xcrypto_xsha0_header__
#define __xcrypto_xsha0_header__

#include <stdint.h>
#include <stddef.h>


enum _xcrypto_sha0_errors {
    SHA0_SUCCESS,
    SHA0_ERR_INVALID_ARG,
    SHA0_ERR_NULL_PTR,
    SHA0_ERR_MEM_ALLOC,
};


struct _xcrypto_sha0_ctx {
    uint32_t H0;
    uint32_t H1;
    uint32_t H2;
    uint32_t H3;
    uint32_t H4;

    uint64_t bits;

    uint8_t buf[64];
    size_t buf_len;

    enum _xcrypto_sha0_errors error;
};


typedef struct _xcrypto_sha0_ctx XSHA0_CTX;
typedef enum _xcrypto_sha0_errors XSHA0_ERRORS;


XSHA0_CTX *XSHA0_Init();
XSHA0_ERRORS XSHA0_Update(XSHA0_CTX *ctx, const uint8_t *buf, size_t bufSize);
XSHA0_ERRORS XSHA0_Finalize(XSHA0_CTX *ctx, uint8_t *buf);


#endif