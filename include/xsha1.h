#ifndef __xcrypto_xsha1_header__
#define __xcrypto_xsha1_header__

#include <stdint.h>
#include <stddef.h>

#define SHA1_DIGEST_LEN 20


enum _xcrypto_sha1_errors {
    SHA1_SUCCESS,
    SHA1_ERR_INVALID_ARG,
    SHA1_ERR_NULL_PTR,
    SHA1_ERR_MEM_ALLOC,
};


struct _xcrypto_sha1_ctx {
    uint32_t H0;
    uint32_t H1;
    uint32_t H2;
    uint32_t H3;
    uint32_t H4;

    uint64_t bits;

    uint8_t buf[64];
    size_t buf_len;

    enum _xcrypto_sha1_errors error;
};


typedef struct _xcrypto_sha1_ctx XSHA1_CTX;
typedef enum _xcrypto_sha1_errors XSHA1_ERRORS;


XSHA1_CTX *XSHA1_Init();
XSHA1_ERRORS XSHA1_Update(XSHA1_CTX *ctx, const uint8_t *buf, size_t bufSize);
XSHA1_ERRORS XSHA1_Finalize(XSHA1_CTX *ctx, uint8_t *buf);


#endif