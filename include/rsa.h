#ifndef __xcrypto_rsa_header__
#define __xcrypto_rsa_header__


#include <stdio.h>
#include <stdint.h>
#include <gmp.h>
#include "rng.h"


enum _rsa_ctx_errors {
    RSA_SUCCESS,
    RSA_ERR_NULL_PTR,
    RSA_ERR_MEM_ALLOC
};


typedef struct rsa_ctx RsaCtx;
typedef enum _rsa_ctx_errors RsaError;


struct rsa_ctx {
    mpz_t p;
    mpz_t q;
    mpz_t n;
    mpz_t phi;
    mpz_t e;
    mpz_t d;
    RsaError error;
};


RsaCtx *RsaInit( size_t keySize, mpz_t exponent );
RsaError freeRsa( RsaCtx *ctx );
mpz_t *RsaEncrypt( RsaCtx *ctx, mpz_t data );
uint8_t *RsaEncryptBuff( RsaCtx *ctx, mpz_t data, size_t *buff_size );
mpz_t *RsaDecrypt( RsaCtx *ctx, mpz_t data );
uint8_t *RsaDecryptBuff( RsaCtx *ctx, mpz_t data, size_t *buff_size );
mpz_t *BytesToLong(uint8_t *buff, size_t buffSize);
uint8_t *LongToBytes(mpz_t data);

#endif