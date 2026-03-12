#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xcrypto.h>


struct aes_cipher {
    size_t key_size;
    uint8_t *key;
    uint8_t state[16];
    uint8_t roundKey[15][16];
} __attribute__((aligned(16)));


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


static void keyExpansion( struct aes_cipher *cipher ) {
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


static void addRoundKey( struct aes_cipher *cipher, uint32_t round ) {
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


static void SubBytes( struct aes_cipher *cipher ) {
    for (int n = 0; n < AES_BLOCK_SIZE; n++)
        cipher->state[n] = _aes_sbox[ cipher->state[n] ];
}


static void UnSubBytes( struct aes_cipher *cipher ) {
    for (int n = 0; n < AES_BLOCK_SIZE; n++)
        cipher->state[n] = _aes_rsbox[ cipher->state[n] ];
}


static void ShiftRows( struct aes_cipher *cipher ) {
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


static void UnShiftRows( struct aes_cipher *cipher ) {
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


static void MixColumns( struct aes_cipher *cipher ) {
    uint8_t r[4];
    uint8_t a[4];
    uint8_t b[4];
    uint8_t h;

    for (uint8_t cnt = 0; cnt < 16; cnt += 4) {
        memcpy(r, (cipher->state + cnt), 4);

        for (uint8_t c = 0; c < 4; c++) {
            a[c] = r[c];
            h = r[c] >> 7;
            b[c] = r[c] << 1;
            b[c] ^= h * 0x1B;
        }

        r[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
        r[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
        r[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
        r[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];
        
        memcpy((cipher->state + cnt), r, 4);
    }
}


uint8_t gmul( uint8_t a, uint8_t b ) {
    uint8_t p = 0;
    uint8_t hi_bit_set;
    for (int i = 0; i < 8; i++) {
        if (b & 1)
            p ^= a;
        hi_bit_set = a & 0x80;
        a <<= 1;
        if (hi_bit_set)
            a ^= 0x1B;
        b >>= 1;
    }
    return p;
}


static void UnMixColumns( struct aes_cipher *cipher ) {
    if (!cipher)
        return;

    uint8_t *s = cipher->state;
    uint8_t col[4];

    for (int c = 0; c < 16; c += 4) {
        col[0] = s[c];
        col[1] = s[c + 1];
        col[2] = s[c + 2];
        col[3] = s[c + 3];

        s[c]     = gmul(col[0], 14) ^ gmul(col[1], 11) ^ gmul(col[2], 13) ^ gmul(col[3], 9);
        s[c + 1] = gmul(col[0], 9)  ^ gmul(col[1], 14) ^ gmul(col[2], 11) ^ gmul(col[3], 13);
        s[c + 2] = gmul(col[0], 13) ^ gmul(col[1], 9)  ^ gmul(col[2], 14) ^ gmul(col[3], 11);
        s[c + 3] = gmul(col[0], 11) ^ gmul(col[1], 13) ^ gmul(col[2], 9)  ^ gmul(col[3], 14);
    }
}


void _aes_encryptor( struct aes_cipher *cipher, const uint8_t *plaintext ) {
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


void _aes_decryptor( struct aes_cipher *cipher, const uint8_t *ciphertext ) {
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


struct aes_cipher * aes_init( const uint8_t *key, size_t keyLength ) {
    if (!(keyLength == 16 || keyLength == 24 || keyLength == 32))
        return NULL;
    
    struct aes_cipher *cipher;

    cipher = (struct aes_cipher *)malloc(sizeof(struct aes_cipher));

    if (!cipher)
        return NULL;

    memset(cipher, 0, sizeof(struct aes_cipher));
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


void free_aes( struct aes_cipher *cipher, bool dynamic ) {
    if (!cipher)
        return;

    memset(cipher->key, 0, cipher->key_size);

    if (dynamic)
        free(cipher->key);

    memset(cipher, 0, sizeof(struct aes_cipher));

    if (dynamic)
        free(cipher);
}
