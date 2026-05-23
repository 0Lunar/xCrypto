#include "cipher.h"
#include "aes.h"
#include "des.h"
#include <memory.h>


CipherCTX *NewCipher(Ciphers cipher, CipherModes mode, const uint8_t *key, size_t keyLength) {
    struct _generic_cipher *new_cipher;

    if ((new_cipher = malloc(sizeof(struct _generic_cipher))) == NULL) {
        perror("Cipher allocation error");
        return NULL;
    }

    memset(new_cipher, 0, sizeof(struct _generic_cipher));
    new_cipher->cipher = cipher;
    new_cipher->mode = mode;

    switch (cipher) {
        case AES:
            new_cipher->ctx = aes_init(key, keyLength);
            break;
        
        case DES:
            new_cipher->ctx = des_init(key);
            break;
        
        default:
            perror("Invalid cipher");
            free(new_cipher);
            return NULL;
    }

    return new_cipher;
}


void SetIV(CipherCTX *ctx, const uint8_t *iv) {
    if (!ctx || !iv)
        return;

    memcpy(ctx->iv, iv, 16ULL);
}


static void _bitwise_xor(uint8_t *__src, uint8_t *__dst, size_t __len) {
    for (size_t __n = 0; __n < __len; __n++)
        __src[__n] ^= __dst[__n];
}


void _ECB_encrypt(CipherCTX *ctx, const uint8_t *plaintext, size_t plaintextLength) {
    if (!ctx || !plaintext || plaintextLength == 0)
        return;
    
    switch (ctx->cipher) {
        case AES:
            if (plaintextLength % AES_BLOCK_SIZE != 0)
                return;

            if (!(ctx->out = malloc(plaintextLength))) {
                perror("Memory allocation error");
                return;
            }
            
            for (size_t n = 0; n < plaintextLength; n += AES_BLOCK_SIZE) {
                _aes_encryptor(ctx->ctx, (plaintext + n));
                memcpy((ctx->out + n), ((struct aes_cipher *)(ctx->ctx))->state, AES_BLOCK_SIZE);
            }
            break;
        
        case DES:
            if (plaintextLength % DES_BLOCK_SIZE != 0)
                return;

            if (!(ctx->out = malloc(plaintextLength))) {
                perror("Memory allocation error");
                return;
            }

            for (size_t n = 0; n < plaintextLength; n += DES_BLOCK_SIZE) {
                _des_encryptor(ctx->ctx, (plaintext + n));
                memcpy((ctx->out + n), &(((struct des_cipher *)(ctx->ctx))->block), DES_BLOCK_SIZE);
            }
        default:
            break;
    }
}


void _ECB_decrypt(CipherCTX *ctx, const uint8_t *ciphertext, size_t ciphertextLength) {
    if (!ctx || !ciphertext || ciphertextLength == 0)
        return;
    
    switch (ctx->cipher) {
        case AES:
            if (ciphertextLength % AES_BLOCK_SIZE != 0)
                return;

            if (!(ctx->out = malloc(ciphertextLength))) {
                perror("Memory allocation error");
                return;
            }
            
            for (size_t n = 0; n < ciphertextLength; n += AES_BLOCK_SIZE) {
                _aes_decryptor(ctx->ctx, (ciphertext + n));
                memcpy((ctx->out + n), ((struct aes_cipher *)(ctx->ctx))->state, AES_BLOCK_SIZE);
            }
            break;
        
        case DES:
            if (ciphertextLength % DES_BLOCK_SIZE != 0)
                return;

            if (!(ctx->out = malloc(ciphertextLength))) {
                perror("Memory allocation error");
                return;
            }

            for (size_t n = 0; n < ciphertextLength; n += DES_BLOCK_SIZE) {
                _des_decryptor(ctx->ctx, (ciphertext + n));
                memcpy((ctx->out + n), &(((struct des_cipher *)(ctx->ctx))->block), DES_BLOCK_SIZE);
            }
        default:
            break;
    }
}


uint8_t *CipherPop(CipherCTX *ctx) {
    uint8_t *tmp;

    tmp = ctx->out;
    ctx->out = NULL;

    return tmp;
}