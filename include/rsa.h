#ifndef __xcrypto_rsa_header__
#define __xcrypto_rsa_header__


#include <stddef.h>
#include <stdint.h>
#include <gmp.h>
#include "rng.h"


enum _xcrypto_rsa_ctx_errors {
    RSA_SUCCESS,
    RSA_ERR_NULL_PTR,
    RSA_ERR_MEM_ALLOC,
    RSA_ERR_INVALID_ARG
};


typedef struct _xcrypto_rsa_ctx RsaCtx;
typedef enum _xcrypto_rsa_ctx_errors RsaError;


struct _xcrypto_rsa_ctx {
    mpz_t p;
    mpz_t q;
    mpz_t n;
    mpz_t phi;
    mpz_t e;
    mpz_t d;
    mpz_t data;
    RsaError error;
};


RsaCtx *NewRsa( size_t keySize, mpz_t exponent );
RsaError FreeRsa( RsaCtx *ctx );
RsaError RsaEncrypt( RsaCtx *ctx, const mpz_t plaintext, mpz_t ciphertext );
RsaError RsaDecrypt( RsaCtx *ctx, const mpz_t ciphertext, mpz_t plaintext );
RsaError BytesToLong(uint8_t *buf, size_t bufSize, mpz_t converted);
RsaError LongToBytes(mpz_t data, uint8_t *buf, size_t *bufLen);
RsaError RsaGetError(struct _xcrypto_rsa_ctx *ctx);

extern const uint8_t *RsaGetErrorString[];

#endif