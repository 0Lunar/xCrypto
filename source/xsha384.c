#include "xsha384.h"
#include <stdlib.h>
#include <memory.h>

#define RIGHTROTATE(x,c) (((x) >> (c)) | ((x) << (64 - (c))))
#define FORCE_INLINE __attribute__((always_inline)) inline
#define SHA384_DIGEST_LEN 48


static const uint64_t K[] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
    0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
    0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
    0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
    0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
    0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
    0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};


FORCE_INLINE void _add_uint128(struct _xcrypto_sha384_ctx *ctx, uint64_t num) {
    uint64_t tmp;

    tmp = ctx->lo_bits;
    ctx->lo_bits += num;

    if (tmp > ctx->lo_bits)
        ctx->hi_bits++;
}


static void _sha384_digest(struct _xcrypto_sha384_ctx *ctx) {
    uint64_t A;
    uint64_t B;
    uint64_t C;
    uint64_t D;
    uint64_t E;
    uint64_t F;
    uint64_t G;
    uint64_t H;
    uint64_t S0;
    uint64_t S1;
    uint64_t ch;
    uint64_t temp1;
    uint64_t temp2;
    uint64_t maj;
    uint64_t W[80];

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
            ((uint64_t)ctx->buf[i * 8 + 0] << 56) |
            ((uint64_t)ctx->buf[i * 8 + 1] << 48) |
            ((uint64_t)ctx->buf[i * 8 + 2] << 40) |
            ((uint64_t)ctx->buf[i * 8 + 3] << 32) |
            ((uint64_t)ctx->buf[i * 8 + 4] << 24) |
            ((uint64_t)ctx->buf[i * 8 + 5] << 16) |
            ((uint64_t)ctx->buf[i * 8 + 6] << 8)  |
            ((uint64_t)ctx->buf[i * 8 + 7]);
    }

    for (uint8_t i = 16; i < 80; i++) {
        S0 = RIGHTROTATE(W[i-15], 1) ^ RIGHTROTATE(W[i-15], 8) ^ (W[i-15] >> 7);
        S1 = RIGHTROTATE(W[i-2], 19) ^ RIGHTROTATE(W[i-2], 61) ^ (W[i-2] >> 6);
        W[i] = W[i-16] + S0 + W[i-7] + S1;
    }

    for (uint8_t i = 0; i < 80; i++) {
        S1 = RIGHTROTATE(E, 14) ^ RIGHTROTATE(E, 18) ^ RIGHTROTATE(E, 41);
        ch = ( E & F ) ^ ( ~E & G );
        temp1 = H + S1 + ch + K[i] + W[i];
        S0 = RIGHTROTATE(A, 28) ^ RIGHTROTATE(A, 34) ^ RIGHTROTATE(A, 39);
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


struct _xcrypto_sha384_ctx *XSHA384_Init() {
    struct _xcrypto_sha384_ctx *ctx;

    if ((ctx = malloc(sizeof(struct _xcrypto_sha384_ctx))) == NULL)
        return NULL;

    ctx->H0 = 0xcbbb9d5dc1059ed8;
    ctx->H1 = 0x629a292a367cd507;
    ctx->H2 = 0x9159015a3070dd17;
    ctx->H3 = 0x152fecd8f70e5939;
    ctx->H4 = 0x67332667ffc00b31;
    ctx->H5 = 0x8eb44a8768581511;
    ctx->H6 = 0xdb0c2e0d64f98fa7;
    ctx->H7 = 0x47b5481dbefa4fa4;

    memset(ctx->buf, 0, 128);
    ctx->buf_len = 0;
    ctx->hi_bits = 0;
    ctx->lo_bits = 0;
    ctx->error = SHA384_SUCCESS;

    return ctx;
}


enum _xcrypto_sha384_errors XSHA384_Update(struct _xcrypto_sha384_ctx *ctx, const uint8_t *buf, size_t bufSize) {
    if (!ctx)
        return SHA384_ERR_NULL_PTR;
    
    if (!buf) {
        ctx->error = SHA384_ERR_NULL_PTR;
        return SHA384_ERR_NULL_PTR;
    }

    if (bufSize == 0) {
        ctx->error = SHA384_SUCCESS;
        return SHA384_SUCCESS;
    }

    size_t buf_len;
    size_t cnt;

    buf_len = ctx->buf_len + bufSize;
    _add_uint128(ctx, ((uint64_t)bufSize << 3));

    if (buf_len < 128) {
        memcpy(ctx->buf + ctx->buf_len, buf, bufSize);
        ctx->buf_len += bufSize;
    }
    else {
        cnt = 128 - ctx->buf_len;
        memcpy(ctx->buf + ctx->buf_len, buf, cnt);
        _sha384_digest(ctx);
        buf_len -= 128;

        while (buf_len >= 128) {
            memcpy(ctx->buf, buf + cnt, 128);
            _sha384_digest(ctx);
            buf_len -= 128;
            cnt += 128;
        }

        if (buf_len > 0)
            memcpy(ctx->buf, buf + cnt, buf_len);
        
        ctx->buf_len = buf_len;
    }

    ctx->error = SHA384_SUCCESS;
    return SHA384_SUCCESS;
}


enum _xcrypto_sha384_errors XSHA384_Finalize(struct _xcrypto_sha384_ctx *ctx, uint8_t *buf) {
    if (!ctx)
        return SHA384_ERR_NULL_PTR;
    
    if (!buf) {
        ctx->error = SHA384_ERR_NULL_PTR;
        return SHA384_ERR_NULL_PTR;
    }

    uint64_t lo_bits = ctx->lo_bits;
    uint64_t hi_bits = ctx->hi_bits;
    uint64_t HH[6];

    ctx->buf[ctx->buf_len++] = 0x80;

    if (ctx->buf_len > 112) {
        while (ctx->buf_len < 128)
            ctx->buf[ctx->buf_len++] = 0;

        _sha384_digest(ctx);
        ctx->buf_len = 0;
    }

    while (ctx->buf_len < 112)
        ctx->buf[ctx->buf_len++] = 0;

    for (uint8_t i = 0; i < 8; i++) {
        ctx->buf[112 + i] = (uint8_t)(hi_bits >> (56 - 8 * i));
        ctx->buf[120 + i] = (uint8_t)(lo_bits >> (56 - 8 * i));
    }

    _sha384_digest(ctx);

    HH[0] = ctx->H0;
    HH[1] = ctx->H1;
    HH[2] = ctx->H2;
    HH[3] = ctx->H3;
    HH[4] = ctx->H4;
    HH[5] = ctx->H5;

    for (uint8_t i = 0; i < 6; i++) {
        buf[i*8 + 0] = (HH[i] >> 56) & 0xFF;
        buf[i*8 + 1] = (HH[i] >> 48) & 0xFF;
        buf[i*8 + 2] = (HH[i] >> 40) & 0xFF;
        buf[i*8 + 3] = (HH[i] >> 32) & 0xFF;
        buf[i*8 + 4] = (HH[i] >> 24) & 0xFF;
        buf[i*8 + 5] = (HH[i] >> 16) & 0xFF;
        buf[i*8 + 6] = (HH[i] >> 8)  & 0xFF;
        buf[i*8 + 7] = HH[i] & 0xFF;
    }

    ctx->error = SHA384_SUCCESS;
    return SHA384_SUCCESS;
}


enum _xcrypto_sha384_errors XSHA384_Reset(struct _xcrypto_sha384_ctx *ctx) {
    ctx->H0 = 0xcbbb9d5dc1059ed8;
    ctx->H1 = 0x629a292a367cd507;
    ctx->H2 = 0x9159015a3070dd17;
    ctx->H3 = 0x152fecd8f70e5939;
    ctx->H4 = 0x67332667ffc00b31;
    ctx->H5 = 0x8eb44a8768581511;
    ctx->H6 = 0xdb0c2e0d64f98fa7;
    ctx->H7 = 0x47b5481dbefa4fa4;

    memset(ctx->buf, 0, 128);
    ctx->buf_len = 0;
    ctx->hi_bits = 0;
    ctx->lo_bits = 0;

    ctx->error = SHA384_SUCCESS;
    return SHA384_SUCCESS;
}