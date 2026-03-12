#ifndef __xcrypto_rsa_header__
#define __xcrypto_rsa_header__


#include <stdio.h>
#include <stdint.h>
#include <gmp.h>
#include "rng.h"


struct rsa_ctx;


struct rsa_ctx *rsa_init( size_t keySize, mpz_t exponent );
void free_rsa( struct rsa_ctx *ctx );
mpz_t *rsa_encrypt( struct rsa_ctx *ctx, mpz_t data );
uint8_t *rsa_encrypt_buff( struct rsa_ctx *ctx, mpz_t data, size_t *buff_size );
mpz_t *rsa_decrypt( struct rsa_ctx *ctx, mpz_t data );
uint8_t *rsa_decrypt_buff( struct rsa_ctx *ctx, mpz_t data, size_t *buff_size );
mpz_t *bytes_to_long(uint8_t *buff, size_t buffSize);
uint8_t *long_to_bytes(mpz_t data);


typedef struct rsa_ctx RsaCtx;

#endif