#ifndef __xcrypto_des_header__
#define __xcrypto_des_header__


#define DES_BLOCK_SIZE 8
#define DES_BLOCK_SIZE_BITS 64
#define DES_ROUNDS 16

// OpenSSL Optimization for IP
#define PERM_OP(a,b,t,n,m) \
{                          \
    t = ((a >> n) ^ b) & m; \
    b ^= t;                \
    a ^= (t << n);         \
}


#include <stdio.h>
#include <stdint.h>


extern const uint8_t _des_ip_table[];


#endif