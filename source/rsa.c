#include "xcrypto/rsa.h"
#include "xcrypto/rng.h"
#include <stdlib.h>
#include <memory.h>


struct _xcrypto_rsa_ctx *NewRsa( size_t keySize, mpz_t exponent ) {
    if (!exponent || keySize < 2) {
        return NULL;
    }

    struct _xcrypto_rsa_ctx *ctx;

    if ((ctx = (struct _xcrypto_rsa_ctx *)malloc(sizeof(struct _xcrypto_rsa_ctx))) == NULL)
        return NULL;

    memset(ctx, 0, sizeof(struct _xcrypto_rsa_ctx));

    mpz_init(ctx->p);
    mpz_init(ctx->q);
    mpz_init(ctx->n);
    mpz_init(ctx->phi);
    mpz_init(ctx->e);
    mpz_init(ctx->d);
    mpz_init(ctx->data);

    mpz_set(ctx->e, exponent);
    GenPrime(ctx->p, keySize / 2);
    GenPrime(ctx->q, keySize / 2);
    mpz_mul(ctx->n, ctx->p, ctx->q);
    mpz_sub_ui(ctx->p, ctx->p, 1ULL);
    mpz_sub_ui(ctx->q, ctx->q, 1ULL);
    mpz_mul(ctx->phi, ctx->p, ctx->q);
    mpz_add_ui(ctx->p, ctx->p, 1ULL);
    mpz_add_ui(ctx->q, ctx->q, 1ULL);
    mpz_invert(ctx->d, ctx->e, ctx->phi);
    ctx->error = RSA_SUCCESS;

    return ctx;
}


enum _xcrypto_rsa_ctx_errors FreeRsa( struct _xcrypto_rsa_ctx *ctx ) {
    if (!ctx)
        return RSA_ERR_NULL_PTR;

    mpz_clears(ctx->p, ctx->q, ctx->n, ctx->phi, ctx->e, ctx->d, ctx->data, NULL);
    free(ctx);

    return RSA_SUCCESS;
}


enum _xcrypto_rsa_ctx_errors RsaEncrypt( struct _xcrypto_rsa_ctx *ctx, const mpz_t plaintext, mpz_t ciphertext ) {
    if (!ctx)
        return RSA_ERR_NULL_PTR;
    
    mpz_powm(ciphertext, plaintext, ctx->e, ctx->n);

    ctx->error = RSA_SUCCESS;
    return RSA_SUCCESS;
}


enum _xcrypto_rsa_ctx_errors RsaDecrypt( struct _xcrypto_rsa_ctx *ctx, const mpz_t ciphertext, mpz_t plaintext ) {
    if (!ctx)
        return RSA_ERR_NULL_PTR;

    mpz_powm(plaintext, ciphertext, ctx->d, ctx->n);

    ctx->error = RSA_SUCCESS;
    return RSA_SUCCESS;
}


enum _xcrypto_rsa_ctx_errors BytesToLong(uint8_t *buf, size_t bufSize, mpz_t converted) {
    if (!buf)
        return RSA_ERR_NULL_PTR;

    if (bufSize == 0)
        return RSA_ERR_INVALID_ARG;

    mpz_import(converted, bufSize, 1, 1, 1, 0, buf);
    return RSA_ERR_INVALID_ARG;
}


enum _xcrypto_rsa_ctx_errors LongToBytes( mpz_t data, uint8_t *buf, size_t *bufLen ) {
    if (!buf || !bufLen)
        return RSA_ERR_NULL_PTR;

    mpz_export(
        buf,
        bufLen,
        1,
        1,
        1,
        0,
        data
    );

    return RSA_SUCCESS;
}


enum _xcrypto_rsa_ctx_errors RsaGetError(struct _xcrypto_rsa_ctx *ctx) {
    if (!ctx)
        return RSA_ERR_NULL_PTR;
    
    return ctx->error;
}


const uint8_t *RsaGetErrorString[] = {
    [RSA_SUCCESS] = "Success",
    [RSA_ERR_NULL_PTR] = "Parameter with null pointer",
    [RSA_ERR_MEM_ALLOC] = "Error allocating memory to heap",
    [RSA_ERR_INVALID_ARG] = "Invalid argument"
};