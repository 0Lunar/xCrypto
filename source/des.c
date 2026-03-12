#include "des.h"
#include <stdlib.h>


struct des_cipher
{
    uint64_t block;
    uint64_t key;
    uint64_t subkeys[16];
};



static void permutedChoice_1( struct des_cipher *cipher, uint32_t *C0, uint32_t *D0 )
{
    uint32_t c = 0, d = 0;
    uint64_t key = cipher->key;

    for (int n = 0; n < 16; n++) {
        uint8_t nv = (uint8_t)((key >> (60 - n * 4)) & 0xF);
        c |= _des_c_table[n][nv];
        d |= _des_d_table[n][nv];
    }

    *C0 = c;
    *D0 = d;
}


static uint64_t permutedChoice_2( uint32_t C, uint32_t D )
{
    uint64_t cd = ((uint64_t)C << 28) | D;
    uint64_t k  = 0;

    for (int n = 0; n < 14; n++) {
        uint8_t nv = (uint8_t)((cd >> (52 - n * 4)) & 0xF);
        k |= _des_pc2_table[n][nv];
    }

    return k;
}


static uint32_t leftShift( uint32_t val, uint8_t round ) {
    if (round == 1 || round == 2 || round == 9 || round == 16)
        return (val << 1 | val >> 27) & 0xFFFFFFF;

    return (val << 2 | val >> 26) & 0xFFFFFFF;
}


void keyTransformation( struct des_cipher *cipher ) {
    uint32_t C, D;

    permutedChoice_1(cipher, &C, &D);

    for (int n = 0; n < DES_ROUNDS; n++) {
        C = leftShift(C, n + 1);
        D = leftShift(D, n + 1);

        cipher->subkeys[n] = permutedChoice_2(C, D);
    }
}


static void initialPermutation( struct des_cipher *cipher ) {
    uint64_t out = 0;
    uint64_t block = cipher->block;

    for (int i = 0; i < 64; i++) {
        int bit = (block >> (64 - _ip_table[i])) & 1;
        out |= (uint64_t)bit << (63 - i);
    }

    cipher->block = out;
}


static uint64_t expansionPermutation( uint32_t R ) {
    return
        (uint64_t)( R        & 0x00000001) << 47 |
        (uint64_t)((R >> 27) & 0x0000001F) << 42 |
        (uint64_t)((R >> 23) & 0x0000003F) << 36 |
        (uint64_t)((R >> 19) & 0x0000003F) << 30 |
        (uint64_t)((R >> 15) & 0x0000003F) << 24 |
        (uint64_t)((R >> 11) & 0x0000003F) << 18 |
        (uint64_t)((R >>  7) & 0x0000003F) << 12 |
        (uint64_t)((R >>  3) & 0x0000003F) <<  6 |
        (uint64_t)( R        & 0x0000001F) <<  1 |
        (uint64_t)((R >> 31) & 0x00000001);
}


static uint32_t substitution( uint64_t expBlock ) {
    uint32_t result = 0;

    for (int i = 0; i < 8; i++) {
        uint8_t b   = (uint8_t)((expBlock >> (42 - i * 6)) & 0x3F);
        uint8_t row = ((b & 0x20) >> 4) | (b & 0x01);
        uint8_t col = (b >> 1) & 0x0F;
        result |= (uint32_t)_des_sbox[i][row * 16 + col] << (28 - i * 4);
    }

    return result;
}


static uint32_t transposition( uint32_t block ) {
    uint32_t res = 0;

    for (int n = 0; n < 32; n++)
        res |= ((block >> (32 - _des_pbox[n])) & 0x01) << (31 - n);

    return res;
}


static void finalPermutation( struct des_cipher *cipher ) {
    uint64_t out = 0;
    uint64_t block = cipher->block;

    for (int i = 0; i < 64; i++) {
        int bit = (block >> (64 - _fp_table[i])) & 1;
        out |= (uint64_t)bit << (63 - i);
    }

    cipher->block = out;
}


void _des_encryptor( struct des_cipher *cipher, const uint8_t *plaintext ) {
    uint32_t L, R, new_R;
    uint64_t expanded_r_block;

    cipher->block = ((uint64_t)plaintext[0] << 56) |
                    ((uint64_t)plaintext[1] << 48) |
                    ((uint64_t)plaintext[2] << 40) |
                    ((uint64_t)plaintext[3] << 32) |
                    ((uint64_t)plaintext[4] << 24) |
                    ((uint64_t)plaintext[5] << 16) |
                    ((uint64_t)plaintext[6] <<  8) |
                    ((uint64_t)plaintext[7]);

    initialPermutation(cipher);

    L = (uint32_t)(cipher->block >> 32);
    R = (uint32_t)(cipher->block & 0xFFFFFFFF);

    for (int round = 0; round < DES_ROUNDS; round++) {
        expanded_r_block = expansionPermutation(R) ^ cipher->subkeys[round];
        new_R = transposition(substitution(expanded_r_block)) ^ L;
        L = R;
        R = new_R;
    }

    /* swap finale prima di FP */
    cipher->block = ((uint64_t)R << 32) | L;
    finalPermutation(cipher);
}


void _des_decryptor( struct des_cipher *cipher, const uint8_t *ciphertext ) {
    uint32_t L, R, new_R;
    uint64_t expanded_r_block;
 
    cipher->block = ((uint64_t)ciphertext[0] << 56) |
                    ((uint64_t)ciphertext[1] << 48) |
                    ((uint64_t)ciphertext[2] << 40) |
                    ((uint64_t)ciphertext[3] << 32) |
                    ((uint64_t)ciphertext[4] << 24) |
                    ((uint64_t)ciphertext[5] << 16) |
                    ((uint64_t)ciphertext[6] <<  8) |
                    ((uint64_t)ciphertext[7]);
 
    initialPermutation(cipher);
 
    L = (uint32_t)(cipher->block >> 32);
    R = (uint32_t)(cipher->block & 0xFFFFFFFF);
 
    for (int round = 0; round < DES_ROUNDS; round++) {
        expanded_r_block = expansionPermutation(R) ^ cipher->subkeys[DES_ROUNDS - 1 - round];
        new_R = transposition(substitution(expanded_r_block)) ^ L;
        L = R;
        R = new_R;
    }
 
    cipher->block = ((uint64_t)R << 32) | L;
    finalPermutation(cipher);
}


struct des_cipher *des_init( const uint8_t *key ) {
    if (!key)
        return NULL;

    struct des_cipher *cipher;

    if ((cipher = (struct des_cipher *)malloc(sizeof(struct des_cipher))) == NULL)
        return NULL;

    cipher->key = ((uint64_t)key[0] << 56) |
                  ((uint64_t)key[1] << 48) |
                  ((uint64_t)key[2] << 40) |
                  ((uint64_t)key[3] << 32) |
                  ((uint64_t)key[4] << 24) |
                  ((uint64_t)key[5] << 16) |
                  ((uint64_t)key[6] <<  8) |
                  ((uint64_t)key[7]);

    keyTransformation(cipher);

    return cipher;
}


void free_des( struct des_cipher *cipher ) {
    if (cipher)
        free(cipher);
}


void des_block( struct des_cipher *cipher, uint8_t *out ) {
    if (!cipher || !out)
        return;

    out[0] = (uint8_t)((cipher->block >> 56) & 0xFF);
    out[1] = (uint8_t)((cipher->block >> 48) & 0xFF);
    out[2] = (uint8_t)((cipher->block >> 40) & 0xFF);
    out[3] = (uint8_t)((cipher->block >> 32) & 0xFF);
    out[4] = (uint8_t)((cipher->block >> 24) & 0xFF);
    out[5] = (uint8_t)((cipher->block >> 16) & 0xFF);
    out[6] = (uint8_t)((cipher->block >>  8) & 0xFF);
    out[7] = (uint8_t)( cipher->block        & 0xFF);
}