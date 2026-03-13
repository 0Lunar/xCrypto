#ifndef __xcrypto_pad_header__
#define __xcrypto_pad_header__


#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


uint8_t *pkcs7_pad( const uint8_t *msg, const size_t msgLen, const size_t padSize );
uint8_t *pkcs7_unpad( const uint8_t *padded, const size_t paddedLen );
uint8_t *x923_pad( const uint8_t *msg, const size_t msgLen, const size_t padSize );
uint8_t *x923_unpad( const uint8_t *padded, const size_t paddedLen );


#endif