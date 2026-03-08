#include <xcrypto.h>


struct des_cipher
{
    uint8_t block[8];
    uint8_t key[8];
    uint8_t subkeys[16][8];
};



static void InitialPermutation(struct des_cipher *cipher) {
    uint64_t block = *(uint64_t *)cipher->block;
    uint64_t result;
    uint8_t shift;

    if (!IS_LITTLE_ENDIAN()) {
        for (int n = 0; n < 64; n++) {
            shift = _des_ip_table[n] - 1;
            result |= ((block >> shift) & 0x1) << (63 - n);
        }
    }
    else {
        // TODO LITTLE ENDIAN SUPPORT
    }

    *(uint64_t *)cipher->block = result;
}