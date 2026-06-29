#include <stdlib.h>
#include <memory.h>
#include "xcrypto/aes.h"

#define IS_LITTLE_ENDIAN() ((*(uint8_t*)&(uint16_t){1}) == 1)

extern const uint8_t _aes_sbox[];
extern const uint8_t _aes_rsbox[];


static const uint8_t rcon[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};


static void RotWord( uint8_t word[4] ) {
    if (!IS_LITTLE_ENDIAN())
        *(uint32_t *)word = *(uint32_t *)word << 8 | *(uint32_t *)word >> 24;
    else
        *(uint32_t *)word = *(uint32_t *)word >> 8 | *(uint32_t *)word << 24;
}


static void SubWord( uint8_t word[4] ) {
    word[0] = _aes_sbox[word[0]];
    word[1] = _aes_sbox[word[1]];
    word[2] = _aes_sbox[word[2]];
    word[3] = _aes_sbox[word[3]];
}


static void keyExpansion( struct _xcrypto_aes_cipher *cipher ) {
    const uint8_t Nb = 4;
    uint8_t Nk = (cipher->key_size >> 2) & 0xFF;
    uint8_t Nr = 6 + Nk;
    uint8_t temp[4];
    uint16_t total_bytes;
    uint16_t cnt;

    memcpy(*cipher->roundKey, cipher->key, cipher->key_size);

    total_bytes = Nb * (Nr + 1) * 4;
    cnt = cipher->key_size & 0xFFFF;

    while (cnt < total_bytes) {
        memcpy(temp, (*cipher->roundKey + cnt - 4), 4);

        if ((cnt / 4) % Nk == 0) { 
            RotWord(temp);
            SubWord(temp);
            temp[0] ^= rcon[(cnt/4)/Nk -1];
        }
        else if (Nk > 6 && ((cnt/4) % Nk) == 4) {
            SubWord(temp);
        }

        *(*cipher->roundKey + cnt) = *(*cipher->roundKey + cnt - Nk * 4) ^ temp[0];
        *(*cipher->roundKey + cnt + 1) = *(*cipher->roundKey + cnt - Nk * 4 + 1) ^ temp[1];
        *(*cipher->roundKey + cnt + 2) = *(*cipher->roundKey + cnt - Nk * 4 + 2) ^ temp[2];
        *(*cipher->roundKey + cnt + 3) = *(*cipher->roundKey + cnt - Nk * 4 + 3) ^ temp[3];
        cnt += 4;
    }
}


static void addRoundKey( struct _xcrypto_aes_cipher *cipher, uint32_t round ) {
#if defined(__x86_64__) || defined(_M_X64)
    *(uint64_t *)cipher->state ^= *(uint64_t *)cipher->roundKey[round];
    *(uint64_t *)(cipher->state + 8) ^= *(uint64_t *)(cipher->roundKey[round] + 8);

#elif defined(__i386__)
    *(uint32_t *)cipher->state ^= *(uint32_t *)cipher->roundKey[round];
    *(uint32_t *)(cipher->state + 4) ^= *(uint32_t *)(cipher->roundKey[round] + 4);
    *(uint32_t *)(cipher->state + 8) ^= *(uint32_t *)(cipher->roundKey[round] + 8);
    *(uint32_t *)(cipher->state + 12) ^= *(uint32_t *)(cipher->roundKey[round] + 12);

#else
    for (int n = 0; n < AES_BLOCK_SIZE; n++)
        cipher->state[n] ^= cipher->roundKey[round][n];
#endif
}


static void SubBytes( struct _xcrypto_aes_cipher *cipher ) {
    for (int n = 0; n < AES_BLOCK_SIZE; n++)
        cipher->state[n] = _aes_sbox[ cipher->state[n] ];
}


static void UnSubBytes( struct _xcrypto_aes_cipher *cipher ) {
    for (int n = 0; n < AES_BLOCK_SIZE; n++)
        cipher->state[n] = _aes_rsbox[ cipher->state[n] ];
}


static void ShiftRows( struct _xcrypto_aes_cipher *cipher ) {
    uint8_t temp;
    uint8_t *state = cipher->state;

    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    temp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp;
}


static void UnShiftRows( struct _xcrypto_aes_cipher *cipher ) {
    uint8_t temp;
    uint8_t *state = cipher->state;

    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;

    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;
}


static inline uint8_t xtime( uint8_t x ) {
    return (x << 1) ^ ((x & 0x80) ? 0x1B : 0);
}


static inline void inv_mul( uint8_t a, uint8_t *m9, uint8_t *m11, uint8_t *m13, uint8_t *m14 ) {
    uint8_t x2 = xtime(a);
    uint8_t x4 = xtime(x2);
    uint8_t x8 = xtime(x4);

    *m9  = x8 ^ a;
    *m11 = x8 ^ x2 ^ a;
    *m13 = x8 ^ x4 ^ a;
    *m14 = x8 ^ x4 ^ x2;
}


static void MixColumns( struct _xcrypto_aes_cipher *cipher ) {
    uint8_t *s = cipher->state;

    for (int c = 0; c < 16; c += 4) {
        uint8_t a0 = s[c];
        uint8_t a1 = s[c + 1];
        uint8_t a2 = s[c + 2];
        uint8_t a3 = s[c + 3];

        uint8_t x0 = xtime(a0);
        uint8_t x1 = xtime(a1);
        uint8_t x2 = xtime(a2);
        uint8_t x3 = xtime(a3);

        s[c]     = x0 ^ (x1 ^ a1) ^ a2 ^ a3;
        s[c + 1] = a0 ^ x1 ^ (x2 ^ a2) ^ a3;
        s[c + 2] = a0 ^ a1 ^ x2 ^ (x3 ^ a3);
        s[c + 3] = (x0 ^ a0) ^ a1 ^ a2 ^ x3;
    }
}


static void UnMixColumns( struct _xcrypto_aes_cipher *cipher ) {
    uint8_t *s = cipher->state;

    for (int c = 0; c < 16; c += 4) {
        uint8_t a0 = s[c];
        uint8_t a1 = s[c + 1];
        uint8_t a2 = s[c + 2];
        uint8_t a3 = s[c + 3];

        uint8_t a09, a11, a13, a14;
        uint8_t b09, b11, b13, b14;
        uint8_t c09, c11, c13, c14;
        uint8_t d09, d11, d13, d14;

        inv_mul(a0, &a09, &a11, &a13, &a14);
        inv_mul(a1, &b09, &b11, &b13, &b14);
        inv_mul(a2, &c09, &c11, &c13, &c14);
        inv_mul(a3, &d09, &d11, &d13, &d14);

        s[c]     = a14 ^ b11 ^ c13 ^ d09;
        s[c + 1] = a09 ^ b14 ^ c11 ^ d13;
        s[c + 2] = a13 ^ b09 ^ c14 ^ d11;
        s[c + 3] = a11 ^ b13 ^ c09 ^ d14;
    }
}


void AesEncryptor( struct _xcrypto_aes_cipher *cipher, const uint8_t *plaintext ) {
    uint8_t rounds = 6 + ((cipher->key_size >> 2) & 0xFF);

    memcpy(cipher->state, plaintext, 16);
    addRoundKey(cipher, 0);

    for (uint8_t rnd = 1; rnd < rounds; rnd++) {
        SubBytes(cipher);
        ShiftRows(cipher);
        MixColumns(cipher);
        addRoundKey(cipher, rnd);
    }

    SubBytes(cipher);
    ShiftRows(cipher);
    addRoundKey(cipher, rounds);
}


void AesDecryptor( struct _xcrypto_aes_cipher *cipher, const uint8_t *ciphertext ) {
    uint8_t rounds = 6 + ((cipher->key_size >> 2) & 0xFF);

    memcpy(cipher->state, ciphertext, 16);
    addRoundKey(cipher, rounds);

    for (int8_t rnd = rounds - 1; rnd >= 0; rnd--) {
        UnShiftRows(cipher);
        UnSubBytes(cipher);
        addRoundKey(cipher, rnd);

        if (rnd > 0)
            UnMixColumns(cipher);
    }
}


struct _xcrypto_aes_cipher * AesInit( const uint8_t *key, size_t keyLength ) {
    if (!(keyLength == 16 || keyLength == 24 || keyLength == 32))
        return NULL;
    
    struct _xcrypto_aes_cipher *cipher;

    cipher = (struct _xcrypto_aes_cipher *)malloc(sizeof(struct _xcrypto_aes_cipher));

    if (!cipher)
        return NULL;

    memset(cipher, 0, sizeof(struct _xcrypto_aes_cipher));
    cipher->key = (uint8_t *)malloc(keyLength);

    if (!cipher->key) {
        free(cipher);
        return NULL;
    }
    
    memcpy(cipher->key, key, keyLength);
    cipher->key_size = keyLength;

    keyExpansion(cipher);

    return cipher;
}


void AesFree( struct _xcrypto_aes_cipher *cipher ) {
    if (!cipher)
        return;
    
    free(cipher);
}


void AesGetBlock( struct _xcrypto_aes_cipher *cipher, uint8_t *buf ) {
    if (!cipher)
        return;
    
    memcpy(buf, cipher->state, AES_BLOCK_SIZE);
}