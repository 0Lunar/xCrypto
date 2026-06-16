#ifndef __xcrypto_xmd5_header__
#define __xcrypto_xmd5_header__

#include <stdint.h>
#include <stddef.h>


enum _xcrypto_md5_errors {
    MD5_SUCCESS,
    MD5_ERR_INVALID_ARG,
    MD5_ERR_NULL_PTR,
    MD5_ERR_MEM_ALLOC,
};


struct _xcrypto_md5_ctx {
    uint32_t A;
    uint32_t B;
    uint32_t C;
    uint32_t D;

    uint64_t bits;

    uint8_t buf[64];
    size_t buf_len;

    enum _xcrypto_md5_errors error;
};


typedef struct _xcrypto_md5_ctx XMD5_CTX;
typedef enum _xcrypto_md5_errors XMD5_ERRORS;


XMD5_CTX *XMD5_Init();
XMD5_ERRORS XMD5_Update(XMD5_CTX *ctx, const uint8_t *buf, size_t bufSize);
XMD5_ERRORS XMD5_Finalize(XMD5_CTX *ctx, uint8_t *buf);
XMD5_ERRORS XMD5_Reset(XMD5_CTX *ctx);

#endif