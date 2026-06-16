#include "xsha256.h"
#include <stdlib.h>
#include <memory.h>


#define RIGHTROTATE(x,c) (((x) >> (c)) | ((x) << (32 - (c))))
#define SHA256_DIGEST_LEN 32


static const uint32_t K[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


static void _sha256_digest(struct _xcrypto_sha256_ctx *ctx) {
    uint32_t A;
    uint32_t B;
    uint32_t C;
    uint32_t D;
    uint32_t E;
    uint32_t F;
    uint32_t G;
    uint32_t H;
    uint32_t S0;
    uint32_t S1;
    uint32_t ch;
    uint32_t temp1;
    uint32_t temp2;
    uint32_t maj;
    uint32_t W[64];

    A = ctx->H0;
    B = ctx->H1;
    C = ctx->H2;
    D = ctx->H3;
    E = ctx->H4;
    F = ctx->H5;
    G = ctx->H6;
    H = ctx->H7;

    for (uint8_t i = 0; i < 16; i++) {
        W[i] =
            ((uint32_t)ctx->buf[i * 4 + 0] << 24) |
            ((uint32_t)ctx->buf[i * 4 + 1] << 16) |
            ((uint32_t)ctx->buf[i * 4 + 2] << 8)  |
            ((uint32_t)ctx->buf[i * 4 + 3]);
    }

    for (uint8_t i = 16; i < 64; i++) {
        S0 = RIGHTROTATE(W[i-15], 7) ^ RIGHTROTATE(W[i-15], 18) ^ (W[i-15] >> 3);
        S1 = RIGHTROTATE(W[i-2], 17) ^ RIGHTROTATE(W[i-2], 19) ^ (W[i-2] >> 10);
        W[i] = W[i-16] + S0 + W[i-7] + S1;
    }

    for (uint8_t i = 0; i < 64; i++) {
        S1 = RIGHTROTATE(E, 6) ^ RIGHTROTATE(E, 11) ^ RIGHTROTATE(E, 25);
        ch = ( E & F ) ^ ( ~E & G );
        temp1 = H + S1 + ch + K[i] + W[i];
        S0 = RIGHTROTATE(A, 2) ^ RIGHTROTATE(A, 13) ^ RIGHTROTATE(A, 22);
        maj = ( A & B ) ^ ( A & C ) ^ ( B & C );
        temp2 = S0 + maj;

        H = G;
        G = F;
        F = E;
        E = D + temp1;
        D = C;
        C = B;
        B = A;
        A = temp1 + temp2;
    }

    ctx->H0 += A;
    ctx->H1 += B;
    ctx->H2 += C;
    ctx->H3 += D;
    ctx->H4 += E;
    ctx->H5 += F;
    ctx->H6 += G;
    ctx->H7 += H;
}


struct _xcrypto_sha256_ctx *XSHA256_Init() {
    struct _xcrypto_sha256_ctx *ctx;

    if ((ctx = malloc(sizeof(struct _xcrypto_sha256_ctx))) == NULL)
        return NULL;

    ctx->H0 = 0x6a09e667;
    ctx->H1 = 0xbb67ae85;
    ctx->H2 = 0x3c6ef372;
    ctx->H3 = 0xa54ff53a;
    ctx->H4 = 0x510e527f;
    ctx->H5 = 0x9b05688c;
    ctx->H6 = 0x1f83d9ab;
    ctx->H7 = 0x5be0cd19;

    memset(ctx->buf, 0, 64);
    ctx->buf_len = 0;
    ctx->bits = 0;
    ctx->error = SHA256_SUCCESS;

    return ctx;
}


enum _xcrypto_sha256_errors XSHA256_Update(struct _xcrypto_sha256_ctx *ctx, const uint8_t *buf, size_t bufSize) {
    if (!ctx)
        return SHA256_ERR_NULL_PTR;
    
    if (!buf) {
        ctx->error = SHA256_ERR_NULL_PTR;
        return SHA256_ERR_NULL_PTR;
    }

    if (bufSize == 0) {
        ctx->error = SHA256_SUCCESS;
        return SHA256_SUCCESS;
    }

    size_t buf_len;
    size_t cnt;

    buf_len = ctx->buf_len + bufSize;
    ctx->bits += ((uint64_t)bufSize << 3);

    if (buf_len < 64) {
        memcpy(ctx->buf + ctx->buf_len, buf, bufSize);
        ctx->buf_len += bufSize;
    }
    else {
        cnt = 64 - ctx->buf_len;
        memcpy(ctx->buf + ctx->buf_len, buf, cnt);
        _sha256_digest(ctx);
        buf_len -= 64;

        while (buf_len >= 64) {
            memcpy(ctx->buf, buf + cnt, 64);
            _sha256_digest(ctx);
            buf_len -= 64;
            cnt += 64;
        }

        if (buf_len > 0)
            memcpy(ctx->buf, buf + cnt, buf_len);
        
        ctx->buf_len = buf_len;
    }

    ctx->error = SHA256_SUCCESS;
    return SHA256_SUCCESS;
}


enum _xcrypto_sha256_errors XSHA256_Finalize(struct _xcrypto_sha256_ctx *ctx, uint8_t *buf) {
    if (!ctx)
        return SHA256_ERR_NULL_PTR;
    
    if (!buf) {
        ctx->error = SHA256_ERR_NULL_PTR;
        return SHA256_ERR_NULL_PTR;
    }

    uint64_t bits = ctx->bits;
    uint32_t HH[8];

    ctx->buf[ctx->buf_len++] = 0x80;

    if (ctx->buf_len > 56) {
        while (ctx->buf_len < 64)
            ctx->buf[ctx->buf_len++] = 0;

        _sha256_digest(ctx);
        ctx->buf_len = 0;
    }

    while (ctx->buf_len < 56)
        ctx->buf[ctx->buf_len++] = 0;

    for (uint8_t i = 0; i < 8; i++)
        ctx->buf[56 + i] = (uint8_t)(bits >> (56 - 8 * i));

    _sha256_digest(ctx);

    HH[0] = ctx->H0;
    HH[1] = ctx->H1;
    HH[2] = ctx->H2;
    HH[3] = ctx->H3;
    HH[4] = ctx->H4;
    HH[5] = ctx->H5;
    HH[6] = ctx->H6;
    HH[7] = ctx->H7;

    for (uint8_t i = 0; i < 8; i++) {
        buf[i*4 + 0] = (HH[i] >> 24) & 0xFF;
        buf[i*4 + 1] = (HH[i] >> 16) & 0xFF;
        buf[i*4 + 2] = (HH[i] >> 8)  & 0xFF;
        buf[i*4 + 3] = HH[i] & 0xFF;
    }

    ctx->error = SHA256_SUCCESS;
    return SHA256_SUCCESS;
}


enum _xcrypto_sha256_errors XSHA256_Reset(struct _xcrypto_sha256_ctx *ctx) {
    ctx->H0 = 0x6a09e667;
    ctx->H1 = 0xbb67ae85;
    ctx->H2 = 0x3c6ef372;
    ctx->H3 = 0xa54ff53a;
    ctx->H4 = 0x510e527f;
    ctx->H5 = 0x9b05688c;
    ctx->H6 = 0x1f83d9ab;
    ctx->H7 = 0x5be0cd19;

    memset(ctx->buf, 0, 64);
    ctx->buf_len = 0;
    ctx->bits = 0;
    
    ctx->error = SHA256_SUCCESS;
    return SHA256_SUCCESS;
}