#ifndef XCRYPTO_RNG_HEADER_H
#define XCRYPTO_RNG_HEADER_H


#include <stdio.h>
#include <gmp.h>
#include <stdint.h>


void csprng_buf( void *buf, size_t len );
void GenPrime( mpz_t prime, int bits );


#endif