#include "cipher.h"
#include "aes.h"
#include "des.h"
#include <memory.h>


CipherCtx *NewCipher( void ) {
    struct _generic_cipher *new_cipher;

    if ((new_cipher = malloc(sizeof(struct _generic_cipher))) == NULL) {
        perror("Cipher allocation error");
        return NULL;
    }

    memset(new_cipher, 0, sizeof(struct _generic_cipher));
    new_cipher->error = CIPHER_SUCCESS;

    return new_cipher;
}


CipherError CipherSetAlgorithm(CipherCtx *ctx, Ciphers cipher) {
    if (!ctx)
        return CIPHER_ERR_NULL_PTR;

    switch (cipher) {
        case AES:
        case DES:
            ctx->cipher = cipher;

            if (ctx->ctx)
                free(ctx->ctx);

            break;
        
        default:
            ctx->error = CIPHER_ERR_UNSUPPORTED_ALGO;
            return CIPHER_ERR_UNSUPPORTED_ALGO;
            break;
    }

    ctx->error = CIPHER_SUCCESS;
    return CIPHER_SUCCESS;
}


CipherError CipherSetKey(CipherCtx *ctx, uint8_t *key, size_t keyLength) {
    if (!ctx)
        return CIPHER_ERR_NULL_PTR;
    
    if (!key) {
        ctx->error = CIPHER_ERR_NULL_PTR;
        return CIPHER_ERR_NULL_PTR;
    }

    if (keyLength == 0) {
        ctx->error = CIPHER_ERR_INVALID_ARG;
        return CIPHER_ERR_INVALID_ARG;
    }
    
    if (!ctx->cipher) {
        ctx->error = CIPHER_ERR_MISSING_ALGO;
        return CIPHER_ERR_MISSING_ALGO;
    }

    switch (ctx->cipher) {
        case AES:
            if (keyLength != 16 && keyLength != 24 && keyLength != 32) {
                ctx->error = CIPHER_ERR_INVALID_KEY;
                return CIPHER_ERR_INVALID_KEY;
            }

            ctx->ctx = aes_init(key, keyLength);
            break;
        
        case DES:
            if (keyLength != 8) {
                ctx->error = CIPHER_ERR_INVALID_KEY;
                return CIPHER_ERR_INVALID_KEY;
            }

            ctx->ctx = des_init(key);
            break;
        
        default:
            ctx->error = CIPHER_ERR_UNSUPPORTED_ALGO;
            return CIPHER_ERR_UNSUPPORTED_ALGO;
    }

    ctx->error = CIPHER_SUCCESS;
    return CIPHER_SUCCESS;
}


CipherError CipherSetMode(CipherCtx *ctx, CipherModes mode) {
    if (!ctx)
        return CIPHER_ERR_NULL_PTR;
    
    switch (mode) {
        case ECB:
        case CBC:
        case CTR:
        case OFB:
            ctx->mode = mode;
            break;
        
        default:
            ctx->error = CIPHER_ERR_UNSUPPORTED_MODE;
            return CIPHER_ERR_UNSUPPORTED_MODE;
    }

    ctx->error = CIPHER_SUCCESS;  
    return CIPHER_SUCCESS;  
}


CipherError CipherSetIV(CipherCtx *ctx, const uint8_t *iv, size_t ivLen) {
    if (!ctx)
        return CIPHER_ERR_NULL_PTR;
    
    if (!iv) {
        ctx->error = CIPHER_ERR_NULL_PTR;
        return CIPHER_ERR_NULL_PTR;
    }

    if (ivLen == 0) {
        ctx->error = CIPHER_ERR_INVALID_ARG;
        return CIPHER_ERR_INVALID_ARG;
    }

    if (!ctx->iv)
        if ((ctx->iv = malloc(ivLen)) == NULL) {
            ctx->error = CIPHER_ERR_MEM_ALLOC;
            return CIPHER_ERR_MEM_ALLOC;
        }

    memcpy(ctx->iv, iv, ivLen);
    ctx->error = CIPHER_SUCCESS;
    return CIPHER_SUCCESS;
}


static void _bitwise_xor(uint8_t *__dst, const uint8_t *__src, size_t __len) {
    for (size_t __n = 0; __n < __len; __n++)
        __dst[__n] = __dst[__n] ^ __src[__n];
}


static CipherError _ECB_encrypt(CipherCtx *ctx, const uint8_t *plaintext, size_t plaintextLength) {    
    switch (ctx->cipher) {
        case AES:
            if (plaintextLength % AES_BLOCK_SIZE != 0) {
                ctx->error = CIPHER_ERR_INVALID_PLAINTEXT_SIZE;
                return CIPHER_ERR_INVALID_PLAINTEXT_SIZE;
            }

            if ((ctx->out = malloc(plaintextLength)) == NULL) {
                ctx->error = CIPHER_ERR_MEM_ALLOC;
                return CIPHER_ERR_MEM_ALLOC;
            }
            
            for (size_t n = 0; n < plaintextLength; n += AES_BLOCK_SIZE) {
                _aes_encryptor(ctx->ctx, (plaintext + n));
                memcpy((ctx->out + n), ((struct aes_cipher *)(ctx->ctx))->state, AES_BLOCK_SIZE);
            }
            ctx->outLen = plaintextLength;
            break;
        
        case DES:
            if (plaintextLength % DES_BLOCK_SIZE != 0) {
                ctx->error = CIPHER_ERR_INVALID_PLAINTEXT_SIZE;
                return CIPHER_ERR_INVALID_PLAINTEXT_SIZE;
            }

            if ((ctx->out = malloc(plaintextLength)) == NULL) {
                ctx->error = CIPHER_ERR_MEM_ALLOC;
                return CIPHER_ERR_MEM_ALLOC;
            }

            for (size_t n = 0; n < plaintextLength; n += DES_BLOCK_SIZE) {
                _des_encryptor(ctx->ctx, (plaintext + n));
                des_block(((struct des_cipher *)(ctx->ctx)), (ctx->out + n));
            }
            ctx->outLen = plaintextLength;
            break;

        default:
            ctx->error = CIPHER_ERR_UNSUPPORTED_ALGO;
            return CIPHER_ERR_UNSUPPORTED_ALGO;
    }

    ctx->error = CIPHER_SUCCESS;
    return CIPHER_SUCCESS;
}


static CipherError _ECB_decrypt(CipherCtx *ctx, const uint8_t *ciphertext, size_t ciphertextLength) {
    switch (ctx->cipher) {
        case AES:
            if (ciphertextLength % AES_BLOCK_SIZE != 0) {
                ctx->error = CIPHER_ERR_INVALID_CIPHERTEXT_SIZE;
                return CIPHER_ERR_INVALID_CIPHERTEXT_SIZE;
            }

            if ((ctx->out = malloc(ciphertextLength)) == NULL) {
                ctx->error = CIPHER_ERR_MEM_ALLOC;
                return CIPHER_ERR_MEM_ALLOC;
            }
            
            for (size_t n = 0; n < ciphertextLength; n += AES_BLOCK_SIZE) {
                _aes_decryptor(ctx->ctx, (ciphertext + n));
                memcpy((ctx->out + n), ((struct aes_cipher *)(ctx->ctx))->state, AES_BLOCK_SIZE);
            }
            ctx->outLen = ciphertextLength;
            break;
        
        case DES:
            if (ciphertextLength % DES_BLOCK_SIZE != 0) {
                ctx->error = CIPHER_ERR_INVALID_CIPHERTEXT_SIZE;
                return CIPHER_ERR_INVALID_CIPHERTEXT_SIZE;
            }

            if ((ctx->out = malloc(ciphertextLength)) == NULL) {
                ctx->error = CIPHER_ERR_MEM_ALLOC;
                return CIPHER_ERR_MEM_ALLOC;
            }

            for (size_t n = 0; n < ciphertextLength; n += DES_BLOCK_SIZE) {
                _des_decryptor(ctx->ctx, (ciphertext + n));
                des_block(((struct des_cipher *)(ctx->ctx)), (ctx->out + n));
            }
            ctx->outLen = ciphertextLength;
            break;

        default:
            ctx->error = CIPHER_ERR_UNSUPPORTED_ALGO;
            return CIPHER_ERR_UNSUPPORTED_ALGO;
    }

    ctx->error = CIPHER_SUCCESS;
    return CIPHER_SUCCESS;
}


static CipherError _CBC_encrypt(CipherCtx *ctx, const uint8_t *plaintext, size_t plaintextLength) {
    if (!ctx->iv) {
        ctx->error = CIPHER_ERR_MISSING_IV;
        return CIPHER_ERR_MISSING_IV;
    }
    
    uint8_t *block;

    switch (ctx->cipher) {
        case AES:
            if (plaintextLength % AES_BLOCK_SIZE != 0) {
                ctx->error = CIPHER_ERR_INVALID_PLAINTEXT_SIZE;
                return CIPHER_ERR_INVALID_PLAINTEXT_SIZE;
            }
        
            if ((block = malloc(AES_BLOCK_SIZE)) == NULL) {
                ctx->error = CIPHER_ERR_MEM_ALLOC;
                return CIPHER_ERR_MEM_ALLOC;
            }

            if ((ctx->out = malloc(plaintextLength)) == NULL) {
                free(block);
                ctx->error = CIPHER_ERR_MEM_ALLOC;
                return CIPHER_ERR_MEM_ALLOC;
            }

            memcpy(block, ctx->iv, AES_BLOCK_SIZE);

            for (size_t n = 0; n < plaintextLength; n += AES_BLOCK_SIZE) {
                _bitwise_xor(block, (plaintext + n), AES_BLOCK_SIZE);
                _aes_encryptor(ctx->ctx, block);
                memcpy((ctx->out + n), ((struct aes_cipher *)(ctx->ctx))->state, AES_BLOCK_SIZE);
                memcpy(block, (ctx->out + n), AES_BLOCK_SIZE);
            }
            ctx->outLen = plaintextLength;
            break;
        
        case DES:
            if (plaintextLength % DES_BLOCK_SIZE != 0) {
                ctx->error = CIPHER_ERR_INVALID_PLAINTEXT_SIZE;
                return CIPHER_ERR_INVALID_PLAINTEXT_SIZE;
            }
        
            if ((block = malloc(DES_BLOCK_SIZE)) == NULL) {
                ctx->error = CIPHER_ERR_MEM_ALLOC;
                return CIPHER_ERR_MEM_ALLOC;
            }

            if ((ctx->out = malloc(plaintextLength)) == NULL) {
                free(block);
                ctx->error = CIPHER_ERR_MEM_ALLOC;
                return CIPHER_ERR_MEM_ALLOC;
            }

            memcpy(block, ctx->iv, DES_BLOCK_SIZE);

            for (size_t n = 0; n < plaintextLength; n += DES_BLOCK_SIZE) {
                _bitwise_xor(block, (plaintext + n), DES_BLOCK_SIZE);
                _des_encryptor(((struct des_cipher *)(ctx->ctx)), block);
                des_block(((struct des_cipher *)(ctx->ctx)), (ctx->out + n));
                memcpy(block, (ctx->out + n), DES_BLOCK_SIZE);
            }

            ctx->outLen = plaintextLength;
            break;

        default:
            ctx->error = CIPHER_ERR_UNSUPPORTED_ALGO;
            return CIPHER_ERR_UNSUPPORTED_ALGO;
    }

    free(block);
    ctx->error = CIPHER_SUCCESS;
    return CIPHER_SUCCESS;
}


static CipherError _CBC_decrypt(CipherCtx *ctx, const uint8_t *ciphertext, size_t ciphertextLength) {
    if (!ctx->iv) {
        ctx->error = CIPHER_ERR_MISSING_IV;
        return CIPHER_ERR_MISSING_IV;
    }

    uint8_t *block;

    switch (ctx->cipher) {
        case AES:
            if (ciphertextLength % AES_BLOCK_SIZE != 0) {
                ctx->error = CIPHER_ERR_INVALID_PLAINTEXT_SIZE;
                return CIPHER_ERR_INVALID_PLAINTEXT_SIZE;
            }
        
            if ((block = malloc(AES_BLOCK_SIZE)) == NULL) {
                ctx->error = CIPHER_ERR_MEM_ALLOC;
                return CIPHER_ERR_MEM_ALLOC;
            }

            if ((ctx->out = malloc(ciphertextLength)) == NULL) {
                free(block);
                ctx->error = CIPHER_ERR_MEM_ALLOC;
                return CIPHER_ERR_MEM_ALLOC;
            }

            memcpy(block, ctx->iv, AES_BLOCK_SIZE);

            for (size_t n = 0; n < ciphertextLength; n += AES_BLOCK_SIZE) {
                _aes_decryptor(ctx->ctx, (ciphertext + n));
                memcpy((ctx->out + n), ((struct aes_cipher *)(ctx->ctx))->state, AES_BLOCK_SIZE);
                _bitwise_xor((ctx->out + n), block, AES_BLOCK_SIZE);
                memcpy(block, (ciphertext + n), AES_BLOCK_SIZE);
            }
            ctx->outLen = ciphertextLength;
            break;
        
        case DES:
            if (ciphertextLength % DES_BLOCK_SIZE != 0) {
                ctx->error = CIPHER_ERR_INVALID_PLAINTEXT_SIZE;
                return CIPHER_ERR_INVALID_PLAINTEXT_SIZE;
            }

            if ((block = malloc(DES_BLOCK_SIZE)) == NULL) {
                ctx->error = CIPHER_ERR_MEM_ALLOC;
                return CIPHER_ERR_MEM_ALLOC;
            }

            if (!(ctx->out = malloc(ciphertextLength))) {
                free(block);
                ctx->error = CIPHER_ERR_MEM_ALLOC;
                return CIPHER_ERR_MEM_ALLOC;
            }

            memcpy(block, ctx->iv, DES_BLOCK_SIZE);

            for (size_t n = 0; n < ciphertextLength; n += DES_BLOCK_SIZE) {
                _des_decryptor(ctx->ctx, (ciphertext + n));
                des_block(((struct des_cipher *)(ctx->ctx)), (ctx->out + n));
                _bitwise_xor((ctx->out + n), block, DES_BLOCK_SIZE);
                memcpy(block, (ciphertext + n), DES_BLOCK_SIZE);
            }

            ctx->outLen = ciphertextLength;
            break;

        default:
            ctx->error = CIPHER_ERR_UNSUPPORTED_ALGO;
            return CIPHER_ERR_UNSUPPORTED_ALGO;
    }

    free(block);
    ctx->error = CIPHER_SUCCESS;
    return CIPHER_SUCCESS;
}


CipherError CipherEncrypt(CipherCtx *ctx, uint8_t *plaintext, size_t plaintextLength) {
    if (!ctx)
        return CIPHER_ERR_NULL_PTR;
    
    if (!plaintext) {        
        ctx->error = CIPHER_ERR_NULL_PTR;
        return CIPHER_ERR_NULL_PTR;
    }

    if (plaintextLength == 0) {
        ctx->error = CIPHER_ERR_INVALID_ARG;
        return CIPHER_ERR_INVALID_ARG;
    }
    
    CipherError state;
    
    switch(ctx->mode) {
        case ECB:
            if ((state = _ECB_encrypt(ctx, plaintext, plaintextLength)) != CIPHER_SUCCESS)
                return state;
            break;
        
        case CBC:
            if ((state = _CBC_encrypt(ctx, plaintext, plaintextLength)) != CIPHER_SUCCESS)
                return state;
            break;
        
        default:
            ctx->error = CIPHER_ERR_UNSUPPORTED_MODE;
            return CIPHER_ERR_UNSUPPORTED_MODE;
    }

    ctx->error = CIPHER_SUCCESS;
    return CIPHER_SUCCESS;
}


CipherError CipherDecrypt(CipherCtx *ctx, uint8_t *ciphertext, size_t ciphertextLength) {
    if (!ctx)
        return CIPHER_ERR_NULL_PTR;
    
    if (!ciphertext) {
        ctx->error = CIPHER_ERR_NULL_PTR;
        return CIPHER_ERR_NULL_PTR;
    }

    if (ciphertext == 0) {
        ctx->error = CIPHER_ERR_INVALID_ARG;
        return CIPHER_ERR_INVALID_ARG;
    }
    
    CipherError state;

    switch(ctx->mode) {
        case ECB:
            if ((state = _ECB_decrypt(ctx, ciphertext, ciphertextLength)) != CIPHER_SUCCESS)
                return state;
            break;
        
        case CBC:
            if ((state = _CBC_decrypt(ctx, ciphertext, ciphertextLength)) != CIPHER_SUCCESS)
                return state;
            break;
        
        default:
            ctx->error = CIPHER_ERR_UNSUPPORTED_MODE;
            return CIPHER_ERR_UNSUPPORTED_MODE;
    }

    ctx->error = CIPHER_SUCCESS;
    return CIPHER_SUCCESS;
}


uint8_t *CipherFinalize(CipherCtx *ctx) {
    if (!ctx) {
        return NULL;
    }

    uint8_t *tmp;

    tmp = ctx->out;
    ctx->out = NULL;

    ctx->error = CIPHER_SUCCESS;
    return tmp;
}


CipherError FreeCiphertext(CipherCtx *ctx) {
    if (!ctx) {
        return CIPHER_ERR_NULL_PTR;
    }

    if (ctx->ctx)
        free(ctx->ctx);
    
    if (ctx->iv)
        free(ctx->iv);
    
    if (ctx->tag)
        free(ctx->tag);
    
    free(ctx);

    ctx->error = CIPHER_SUCCESS;
    return CIPHER_SUCCESS;
}


CipherError CipherReset(CipherCtx *ctx, CipherResetMode mode) {
    if (!ctx)
        return CIPHER_ERR_NULL_PTR;

    ctx->cipher = CIPHER_NOT_SET;

    if (ctx->ctx && CIPHER_FULL_RESET)
        free(ctx->ctx);
    
    ctx->ctx = NULL;

    if (ctx->out && CIPHER_FULL_RESET)
        free(ctx->out);

    ctx->out = NULL;
    ctx->outLen = 0;
    ctx->iv = NULL;

    if (ctx->tag && CIPHER_FULL_RESET)
        free(ctx->tag);

    ctx->tag = NULL;
    ctx->error = CIPHER_SUCCESS;
    return CIPHER_SUCCESS;
}


CipherError GetError(CipherCtx *ctx) {
    if (!ctx) {
        return CIPHER_ERR_NULL_PTR;
    }

    return ctx->error;
}


const uint8_t *GetErrorString[] = {
    [CIPHER_SUCCESS] = "Success",
    [CIPHER_ERR_INVALID_ARG] = "Invalid argument",
    [CIPHER_ERR_NULL_PTR] = "Parameter with null pointer",
    [CIPHER_ERR_UNSUPPORTED_ALGO] = "Algorithm not supported or non-existent",
    [CIPHER_ERR_INVALID_KEY] = "Invalid key or incompatible key length",
    [CIPHER_ERR_UNSUPPORTED_MODE] = "Invalid or non-existent mode",
    [CIPHER_ERR_MEM_ALLOC] = "Error allocating memory to heap",
    [CIPHER_ERR_MISSING_ALGO] = "Algorithm not set",
    [CIPHER_ERR_INVALID_BLOCK_SIZE] = "Invalid block size",
    [CIPHER_ERR_INVALID_PLAINTEXT_SIZE] = "Invalid plaintext size (try with padding)",
    [CIPHER_ERR_INVALID_CIPHERTEXT_SIZE] = "Invalid ciphertext size",
    [CIPHER_ERR_MISSING_IV] = "Required IV missing"
};