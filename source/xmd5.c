#include "xmd5.h"
#include <stdlib.h>
#include <memory.h>


#define F(B,C,D)        ((B & C) | (~B & D))
#define G(B,C,D)        ((B & D) | (C & ~D))
#define H(B,C,D)        (B ^ C ^ D)
#define I(B,C,D)        (C ^ (B | ~D))
#define LEFTROTATE(x,c) (((x) << (c)) | ((x) >> (32 - (c))))

#define MD5_DIGEST_LEN 16


static const uint8_t S[] = {
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
};


static const uint32_t K[] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};


static void _md5_digest(struct _xcrypto_md5_ctx *ctx) {
    uint32_t A;
    uint32_t B;
    uint32_t C; 
    uint32_t D;
    uint32_t f;
    uint32_t g;
    uint32_t M[16];

    A = ctx->A;
    B = ctx->B;
    C = ctx->C;
    D = ctx->D;
    
    for (uint8_t i = 0; i < 16; i++) {
        M[i] =
            ((uint32_t)ctx->buf[i * 4 + 0]      ) |
            ((uint32_t)ctx->buf[i * 4 + 1] <<  8) |
            ((uint32_t)ctx->buf[i * 4 + 2] << 16) |
            ((uint32_t)ctx->buf[i * 4 + 3] << 24);
    }

    for (uint8_t n = 0; n < 64; n++) {
        if (n < 16) {
            f = F(B,C,D);
            g = n;
        }
        else if (n < 32) {
            f = G(B,C,D);
            g = (5*n + 1) % 16;
        }
        else if (n < 48) {
            f = H(B,C,D);
            g = (3*n + 5) % 16;
        }
        else {
            f = I(B,C,D);
            g = (7*n) % 16; 
        }

        f = f + A + K[n] + M[g];
        A = D;
        D = C;
        C = B;
        B = B + LEFTROTATE(f, S[n]);
    }

    ctx->A += A;
    ctx->B += B;
    ctx->C += C;
    ctx->D += D;
    ctx->buf_len = 0;
}


struct _xcrypto_md5_ctx *XMD5_Init() {
    struct _xcrypto_md5_ctx *ctx;

    if ((ctx = malloc(sizeof(struct _xcrypto_md5_ctx))) == NULL)
        return NULL;
    
    ctx->A = 0x67452301;
    ctx->B = 0xefcdab89;
    ctx->C = 0x98badcfe;
    ctx->D = 0x10325476;
    memset(ctx->buf, 0, 64);
    ctx->buf_len = 0;
    ctx->bits = 0;

    ctx->error = MD5_SUCCESS;

    return ctx;
}


enum _xcrypto_md5_errors XMD5_Update(struct _xcrypto_md5_ctx *ctx, const uint8_t *buf, size_t bufSize) {
    if (!ctx)
        return MD5_ERR_NULL_PTR;
    
    if (!buf) {
        ctx->error = MD5_ERR_NULL_PTR;
        return MD5_ERR_NULL_PTR;
    }

    if (bufSize == 0) {
        ctx->error = MD5_SUCCESS;
        return MD5_SUCCESS;
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
        _md5_digest(ctx);
        buf_len -= 64;
        ctx->bits += ((uint64_t)cnt << 3);

        while (buf_len >= 64) {
            memcpy(ctx->buf, buf + cnt, 64);
            _md5_digest(ctx);
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

    ctx->error = MD5_SUCCESS;
    return MD5_SUCCESS;
}


enum _xcrypto_md5_errors XMD5_Finalize(struct _xcrypto_md5_ctx *ctx, uint8_t *buf) {
    if (!ctx)
        return MD5_ERR_NULL_PTR;
    
    if (!buf) {
        ctx->error = MD5_ERR_NULL_PTR;
        return MD5_ERR_NULL_PTR;
    }

    uint64_t bits = ctx->bits;

    ctx->buf[ctx->buf_len++] = 0x80;

    if (ctx->buf_len > 56) {
        while (ctx->buf_len < 64)
            ctx->buf[ctx->buf_len++] = 0;

        _md5_digest(ctx);
        ctx->buf_len = 0;
    }

    while (ctx->buf_len < 56)
        ctx->buf[ctx->buf_len++] = 0;

    for (uint8_t i = 0; i < 8; i++)
        ctx->buf[56 + i] = (uint8_t)(bits >> (8 * i));

    _md5_digest(ctx);

    buf[0]  =  ctx->A        & 0xFF;
    buf[1]  = (ctx->A >> 8 ) & 0xFF;
    buf[2]  = (ctx->A >> 16) & 0xFF;
    buf[3]  = (ctx->A >> 24) & 0xFF;
    buf[4]  =  ctx->B        & 0xFF;
    buf[5]  = (ctx->B >> 8 ) & 0xFF;
    buf[6]  = (ctx->B >> 16) & 0xFF;
    buf[7]  = (ctx->B >> 24) & 0xFF;
    buf[8]  =  ctx->C        & 0xFF;
    buf[9]  = (ctx->C >> 8 ) & 0xFF;
    buf[10] = (ctx->C >> 16) & 0xFF;
    buf[11] = (ctx->C >> 24) & 0xFF;
    buf[12] =  ctx->D        & 0xFF;
    buf[13] = (ctx->D >> 8 ) & 0xFF;
    buf[14] = (ctx->D >> 16) & 0xFF;
    buf[15] = (ctx->D >> 24) & 0xFF;

    ctx->error = MD5_SUCCESS;
    return MD5_SUCCESS;
}