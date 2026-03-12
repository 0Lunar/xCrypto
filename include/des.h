#ifndef __xcrypto_des_header__
#define __xcrypto_des_header__


#define DES_BLOCK_SIZE 8
#define DES_BLOCK_SIZE_BITS 64
#define DES_ROUNDS 16
#define SBOX_IDX(b) (((b & 0x20) >> 4) | (b & 0x01)) * 16 + ((b >> 1) & 0x0F)


// OpenSSL Optimization for IP
#define PERM_OP(a,b,t,n,m) \
{                          \
    t = ((a >> n) ^ b) & m; \
    b ^= t;                \
    a ^= (t << n);         \
}


#include <stdio.h>
#include <stdint.h>


struct des_cipher;


struct des_cipher *des_init(const uint8_t *key);
void free_des(struct des_cipher *cipher);
void _des_encryptor(struct des_cipher *cipher, const uint8_t *plaintext);
void _des_decryptor(struct des_cipher *cipher, const uint8_t *ciphertext);
void des_block( struct des_cipher *cipher, uint8_t *out );


extern const uint8_t _ip_table[64];
extern const uint8_t _fp_table[64];
extern const uint32_t _des_c_table[16][16];
extern const uint32_t _des_d_table[16][16];
extern const uint64_t _des_pc2_table[14][16];
extern const uint8_t _des_sbox[8][64];
extern const uint8_t _des_pbox[32];


typedef struct des_cipher DesCipher;


#endif