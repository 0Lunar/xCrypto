#ifndef __xcrypto_rng_header__
#define __xcrypto_rng_header__


#include <stdio.h>
#include <gmp.h>
#include <stdint.h>


void csprng_buf( void *buf, size_t len );
void gen_prime( mpz_t prime, int bits );


#endif