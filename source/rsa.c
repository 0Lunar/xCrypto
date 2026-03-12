#include "rsa.h"
#include <stdlib.h>


struct rsa_ctx {
    mpz_t p;
    mpz_t q;
    mpz_t n;
    mpz_t phi;
    mpz_t e;
    mpz_t d;
};


struct rsa_ctx *rsa_init( size_t keySize, mpz_t exponent ) {
    struct rsa_ctx *ctx;

    if ((ctx = (struct rsa_ctx *)malloc(sizeof(struct rsa_ctx))) == NULL)
        return NULL;

    mpz_init(ctx->p);
    mpz_init(ctx->q);
    mpz_init(ctx->n);
    mpz_init(ctx->phi);
    mpz_init(ctx->e);
    mpz_init(ctx->d);

    mpz_set(ctx->e, exponent);
    gen_prime(ctx->p, keySize / 2);
    gen_prime(ctx->q, keySize / 2);
    mpz_mul(ctx->n, ctx->p, ctx->q);
    mpz_sub_ui(ctx->p, ctx->p, 1ULL);
    mpz_sub_ui(ctx->q, ctx->q, 1ULL);
    mpz_mul(ctx->phi, ctx->p, ctx->q);
    mpz_add_ui(ctx->p, ctx->p, 1ULL);
    mpz_add_ui(ctx->q, ctx->q, 1ULL);
    mpz_invert(ctx->d, ctx->e, ctx->phi);

    return ctx;
}


void free_rsa( struct rsa_ctx *ctx ) {
    if (ctx) {
        mpz_clears(ctx->p, ctx->q, ctx->n, ctx->phi, ctx->e, ctx->d);
        free(ctx);
    }
}


mpz_t *rsa_encrypt( struct rsa_ctx *ctx, mpz_t data ) {
    if (!ctx)
        return NULL;

    mpz_t *encrypted;

    encrypted = (mpz_t *)malloc(sizeof(mpz_t));
    mpz_init(*encrypted);

    mpz_powm(*encrypted, data, ctx->e, ctx->n);

    return encrypted;
}


uint8_t *rsa_encrypt_buff( struct rsa_ctx *ctx, mpz_t data, size_t *buff_size ) {
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
    return buff;
}


mpz_t *rsa_decrypt( struct rsa_ctx *ctx, mpz_t data ) {
    if (!ctx)
        return NULL;

    mpz_t *decrypted;

    decrypted = (mpz_t *)malloc(sizeof(mpz_t));
    mpz_init(*decrypted);

    mpz_powm(*decrypted, data, ctx->d, ctx->n);

    return decrypted;
}


uint8_t *rsa_decrypt_buff( struct rsa_ctx *ctx, mpz_t data, size_t *buff_size ) {
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
    return buff;
}


mpz_t *bytes_to_long(uint8_t *buff, size_t buffSize) {
    mpz_t *res = malloc(sizeof(mpz_t));
    mpz_init(*res);

    mpz_import(*res, buffSize, 1, 1, 1, 0, buff);

    return res;
}


uint8_t *long_to_bytes(mpz_t data) {
    return mpz_get_str(NULL, 10, data);
}