#include "xsha0.h"
#include <stdlib.h>
#include <memory.h>


#define F(B,C,D)        (( B & C ) | ( ~B & D ))
#define G(B,C,D)        (B ^ C ^ D)
#define H(B,C,D)        ((B & C) | (B & D) | (C & D))
#define I(B,C,D)        (B ^ C ^ D)
#define LEFTROTATE(x,c) (((x) << (c)) | ((x) >> (32 - (c))))

#define SHA0_DIGEST_LEN 20


static void _sha0_digest(struct _xcrypto_sha0_ctx *ctx) {
    uint32_t A;
    uint32_t B;
    uint32_t C;
    uint32_t D;
    uint32_t E;
    uint32_t f;
    uint32_t k;
    uint32_t temp;
    uint32_t M[80];

    A = ctx->H0;
    B = ctx->H1;
    C = ctx->H2;
    D = ctx->H3;
    E = ctx->H4;

    for (uint8_t i = 0; i < 16; i++) {
        M[i] =
            ((uint32_t)ctx->buf[i * 4 + 0] << 24) |
            ((uint32_t)ctx->buf[i * 4 + 1] << 16) |
            ((uint32_t)ctx->buf[i * 4 + 2] << 8)  |
            ((uint32_t)ctx->buf[i * 4 + 3]);
    }

    for (uint8_t i = 16; i < 80; i++)
        M[i] = M[i-3] ^ M[i-8] ^ M[i-14] ^ M[i-16];
    
    for (uint8_t i = 0; i < 80; i++) {
        if (i < 20) {
            f = F(B, C, D);
            k = 0x5A827999;
        }
        else if (i < 40) {
            f = G(B, C, D);
            k = 0x6ED9EBA1;
        }
        else if (i < 60) {
            f = H(B, C, D);
            k = 0x8F1BBCDC;
        }
        else {
            f = I(B, C, D);
            k = 0xCA62C1D6;
        }

        temp = LEFTROTATE(A, 5) + f + E + k + M[i];
        E = D;
        D = C;
        C = LEFTROTATE(B, 30);
        B = A;
        A = temp;
    }

    ctx->H0 += A;
    ctx->H1 += B;
    ctx->H2 += C;
    ctx->H3 += D;
    ctx->H4 += E;
}


struct _xcrypto_sha0_ctx *XSHA0_Init() {
    struct _xcrypto_sha0_ctx *ctx;

    if ((ctx = malloc(sizeof(struct _xcrypto_sha0_ctx))) == NULL)
        return NULL;
    
    ctx->H0 = 0x67452301;
    ctx->H1 = 0xEFCDAB89;
    ctx->H2 = 0x98BADCFE;
    ctx->H3 = 0x10325476;
    ctx->H4 = 0xC3D2E1F0;

    memset(ctx->buf, 0, 64);
    ctx->buf_len = 0;
    ctx->bits = 0;
    ctx->error = SHA0_SUCCESS;

    return ctx;
}


enum _xcrypto_sha0_errors XSHA0_Update(struct _xcrypto_sha0_ctx *ctx, const uint8_t *buf, size_t bufSize) {
    if (!ctx)
        return SHA0_ERR_NULL_PTR;
    
    if (!buf) {
        ctx->error = SHA0_ERR_NULL_PTR;
        return SHA0_ERR_NULL_PTR;
    }

    if (bufSize == 0) {
        ctx->error = SHA0_SUCCESS;
        return SHA0_SUCCESS;
    }

    size_t buf_len;
    size_t cnt;

    buf_len = ctx->buf_len + bufSize;

    if (buf_len < 64) {
        memcpy(ctx->buf + ctx->buf_len, buf, bufSize);
        ctx->buf_len += bufSize;
        ctx->bits += ((uint64_t)bufSize << 3);
    }
    else {
        cnt = 64 - ctx->buf_len;
        memcpy(ctx->buf + ctx->buf_len, buf, cnt);
        _sha0_digest(ctx);
        buf_len -= 64;
        ctx->bits += ((uint64_t)cnt << 3);

        while (buf_len >= 64) {
            memcpy(ctx->buf, buf + cnt, 64);
            _sha0_digest(ctx);
            buf_len -= 64;
            cnt += 64;
            ctx->bits += 512;
        }

        if (buf_len > 0) {
            memcpy(ctx->buf, buf + cnt, buf_len);
            ctx->bits += ((uint64_t)buf_len << 3);
        }
        
        ctx->buf_len = buf_len;
    }

    ctx->error = SHA0_SUCCESS;
    return SHA0_SUCCESS;
}


enum _xcrypto_sha0_errors XSHA0_Finalize(struct _xcrypto_sha0_ctx *ctx, uint8_t *buf) {
    if (!ctx)
        return SHA0_ERR_NULL_PTR;
    
    if (!buf) {
        ctx->error = SHA0_ERR_NULL_PTR;
        return SHA0_ERR_NULL_PTR;
    }

    uint64_t bits = ctx->bits;
    uint32_t HH[5];

    ctx->buf[ctx->buf_len++] = 0x80;

    if (ctx->buf_len > 56) {
        while (ctx->buf_len < 64)
            ctx->buf[ctx->buf_len++] = 0;

        _sha0_digest(ctx);
        ctx->buf_len = 0;
    }

    while (ctx->buf_len < 56)
        ctx->buf[ctx->buf_len++] = 0;

    for (uint8_t i = 0; i < 8; i++)
        ctx->buf[56 + i] = (uint8_t)(bits >> (56 - 8 * i));

    _sha0_digest(ctx);

    HH[0] = ctx->H0;
    HH[1] = ctx->H1;
    HH[2] = ctx->H2;
    HH[3] = ctx->H3;
    HH[4] = ctx->H4;

    for (uint8_t i = 0; i < 5; i++) {
        buf[i*4 + 0] = (HH[i] >> 24) & 0xFF;
        buf[i*4 + 1] = (HH[i] >> 16) & 0xFF;
        buf[i*4 + 2] = (HH[i] >> 8)  & 0xFF;
        buf[i*4 + 3] = HH[i] & 0xFF;
    }

    ctx->error = SHA0_SUCCESS;
    return SHA0_SUCCESS;
}