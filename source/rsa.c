#include "rsa.h"
#include <stdlib.h>
#include <memory.h>


RsaCtx *RsaInit( size_t keySize, mpz_t exponent ) {
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


RsaError freeRsa( RsaCtx *ctx ) {
    if (!ctx)
        return RSA_ERR_NULL_PTR;

    mpz_clears(ctx->p, ctx->q, ctx->n, ctx->phi, ctx->e, ctx->d);
    free(ctx);
    ctx->error = RSA_SUCCESS;
}


mpz_t *RsaEncrypt( RsaCtx *ctx, mpz_t data ) {
    if (!ctx)
        return NULL;
    
    if (!data) {
        ctx->error = RSA_ERR_NULL_PTR;
        return NULL;
    }

    mpz_t *encrypted;

    if ((encrypted = (mpz_t *)malloc(sizeof(mpz_t))) == NULL) {
        ctx->error = RSA_ERR_MEM_ALLOC;
        return NULL;
    }
    
    mpz_init(*encrypted);
    mpz_powm(*encrypted, data, ctx->e, ctx->n);

    ctx->error = RSA_SUCCESS;
    return encrypted;
}


uint8_t *RsaEncryptBuff( RsaCtx *ctx, mpz_t data, size_t *buff_size ) {
    if (!ctx)
        return NULL;
    
    if (!data) {
        ctx->error = RSA_ERR_NULL_PTR;
        return NULL;
    }

    mpz_t encrypted;
    uint8_t *buff;

    mpz_init(encrypted);
    mpz_powm(encrypted, data, ctx->e, ctx->n);

    buff = mpz_export(
        NULL,
        buff_size,
        1,
        1,
        1,
        0,
        encrypted
    );

    mpz_clear(encrypted);
    ctx->error = RSA_SUCCESS;
    return buff;
}


mpz_t *RsaDecrypt( RsaCtx *ctx, mpz_t data ) {
    if (!ctx)
        return NULL;

    if (!data) {
        ctx->error = RSA_ERR_NULL_PTR;
        return NULL;
    }

    mpz_t *decrypted;

    decrypted = (mpz_t *)malloc(sizeof(mpz_t));
    mpz_init(*decrypted);

    mpz_powm(*decrypted, data, ctx->d, ctx->n);

    ctx->error = RSA_SUCCESS;
    return decrypted;
}


uint8_t *RsaDecryptBuff( RsaCtx *ctx, mpz_t data, size_t *buff_size ) {
    if (!ctx)
        return NULL;
    
    if (!data) {
        ctx->error = RSA_ERR_NULL_PTR;
        return NULL;
    }

    mpz_t decrypted;
    uint8_t *buff;

    mpz_init(decrypted);
    mpz_powm(decrypted, data, ctx->d, ctx->n);

    buff = mpz_export(
        NULL,
        buff_size,
        1,
        1,
        1,
        0,
        decrypted
    );

    mpz_clear(decrypted);
    ctx->error = RSA_SUCCESS;
    return buff;
}


mpz_t *BytesToLong(uint8_t *buff, size_t buffSize) {
    if (!buff || buffSize == 0)
        return NULL;

    mpz_t *res;

    if ((res = malloc(sizeof(mpz_t))) == NULL)
        return NULL;

    mpz_init(*res);
    mpz_import(*res, buffSize, 1, 1, 1, 0, buff);

    return res;
}


uint8_t *LongToBytes(mpz_t data) {
    if (!data)
        return NULL;

    return mpz_get_str(NULL, 10, data);
}