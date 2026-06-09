#include "cipher.h"
#include "aes.h"
#include "des.h"
#include <memory.h>

#define IS_LITTLE_ENDIAN() ((*(uint8_t*)&(uint16_t){1}) == 1)


struct _xcrypto_generic_cipher *NewCipher( void ) {
    struct _xcrypto_generic_cipher *new_cipher;

    if ((new_cipher = malloc(sizeof(struct _xcrypto_generic_cipher))) == NULL) {
        return NULL;
    }

    memset(new_cipher, 0, sizeof(struct _xcrypto_generic_cipher));
    new_cipher->error = CIPHER_SUCCESS;

    return new_cipher;
}


enum _xcrypto_cipher_op_state CipherSetAlgorithm(struct _xcrypto_generic_cipher *ctx, Ciphers cipher) {
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


enum _xcrypto_cipher_op_state CipherSetKey(struct _xcrypto_generic_cipher *ctx, uint8_t *key, size_t keyLength) {
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


enum _xcrypto_cipher_op_state CipherSetMode(struct _xcrypto_generic_cipher *ctx, CipherModes mode) {
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


enum _xcrypto_cipher_op_state CipherSetIV(struct _xcrypto_generic_cipher *ctx, const uint8_t *iv, size_t ivLen) {
    if (!ctx || !iv)
        return CIPHER_ERR_NULL_PTR;

    if (ctx->cipher == CIPHER_NOT_SET) {
        ctx->cipher = CIPHER_ERR_MISSING_ALGO;
        return CIPHER_ERR_MISSING_ALGO;
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

    memcpy(ctx->iv, iv, CipherBlockSize[ctx->cipher]);
    ctx->ivLen = ivLen;
    ctx->error = CIPHER_SUCCESS;
    return CIPHER_SUCCESS;
}


enum _xcrypto_cipher_op_state CipherSetBuffer(struct _xcrypto_generic_cipher *ctx, uint8_t *buf, size_t bufSize) {
    if (!ctx)
        return CIPHER_ERR_NULL_PTR;

    if (!buf) {
        ctx->error = CIPHER_ERR_NULL_PTR;
        return CIPHER_ERR_NULL_PTR;
    }

    if (bufSize == 0) {
        ctx->error = CIPHER_ERR_INVALID_ARG;
        return CIPHER_ERR_INVALID_ARG;
    }

    ctx->out = buf;
    ctx->maxOutLen = bufSize;
}


static void _bitwise_xor(uint8_t *__dst, const uint8_t *__src, size_t __len) {
    for (size_t __n = 0; __n < __len; __n++)
        __dst[__n] = __dst[__n] ^ __src[__n];
}


static void _inc_nonce(uint8_t *buf, size_t nonceSize) {
    if (!buf || nonceSize == 0)
        return;

    uint8_t carry;
    int32_t cnt;

    carry = 1;
    cnt = nonceSize - 1;

    while (carry && cnt > -1) {
        carry = ((uint16_t)buf[cnt] + 1) >> 8;
        ++buf[cnt];
        cnt--;
    }
}


static enum _xcrypto_cipher_op_state _ECB_encrypt(struct _xcrypto_generic_cipher *ctx, const uint8_t *plaintext, size_t plaintextLength) {    
    if (plaintextLength % CipherBlockSize[ctx->cipher] != 0) {
        ctx->error = CIPHER_ERR_INVALID_PLAINTEXT_SIZE;
        return CIPHER_ERR_INVALID_PLAINTEXT_SIZE;
    }

    if (plaintextLength > ctx->maxOutLen) {
        ctx->error = CIPHER_ERR_BUFFER_OVERFLOW;
        return CIPHER_ERR_BUFFER_OVERFLOW;
    }

    memset(ctx->out, 0, plaintextLength);
    
    switch (ctx->cipher) {
        case AES:            
            for (size_t n = 0; n < plaintextLength; n += AES_BLOCK_SIZE) {
                _aes_encryptor(ctx->ctx, (plaintext + n));
                memcpy((ctx->out + n), ((struct _xcrypto_aes_cipher *)(ctx->ctx))->state, AES_BLOCK_SIZE);
            }
            ctx->outLen = plaintextLength;
            break;
        
        case DES:
            for (size_t n = 0; n < plaintextLength; n += DES_BLOCK_SIZE) {
                _des_encryptor(ctx->ctx, (plaintext + n));
                des_block(((struct _xcrypto_des_cipher *)(ctx->ctx)), (ctx->out + n));
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


static enum _xcrypto_cipher_op_state _ECB_decrypt(struct _xcrypto_generic_cipher *ctx, const uint8_t *ciphertext, size_t ciphertextLength) {
    Ciphers cipher = ctx->cipher;

    if (ciphertextLength % CipherBlockSize[cipher] != 0) {
        ctx->error = CIPHER_ERR_INVALID_CIPHERTEXT_SIZE;
        return CIPHER_ERR_INVALID_CIPHERTEXT_SIZE;
    }

    if (ciphertextLength > ctx->maxOutLen) {
        ctx->error = CIPHER_ERR_BUFFER_OVERFLOW;
        return CIPHER_ERR_BUFFER_OVERFLOW;
    }

    memset(ctx->out, 0, ciphertextLength);
    
    switch (cipher) {
        case AES:
            for (size_t n = 0; n < ciphertextLength; n += AES_BLOCK_SIZE) {
                _aes_decryptor(ctx->ctx, (ciphertext + n));
                memcpy((ctx->out + n), ((struct _xcrypto_aes_cipher *)(ctx->ctx))->state, AES_BLOCK_SIZE);
            }
            ctx->outLen = ciphertextLength;
            break;
        
        case DES:
            for (size_t n = 0; n < ciphertextLength; n += DES_BLOCK_SIZE) {
                _des_decryptor(ctx->ctx, (ciphertext + n));
                des_block(((struct _xcrypto_des_cipher *)(ctx->ctx)), (ctx->out + n));
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


static enum _xcrypto_cipher_op_state _CBC_encrypt(struct _xcrypto_generic_cipher *ctx, const uint8_t *plaintext, size_t plaintextLength) {
    Ciphers cipher = ctx->cipher;
    
    if (!ctx->iv) {
        ctx->error = CIPHER_ERR_MISSING_IV;
        return CIPHER_ERR_MISSING_IV;
    }

    if (plaintextLength % CipherBlockSize[cipher] != 0) {
        ctx->error = CIPHER_ERR_INVALID_CIPHERTEXT_SIZE;
        return CIPHER_ERR_INVALID_CIPHERTEXT_SIZE;
    }

    if (plaintextLength > ctx->maxOutLen) {
        ctx->error = CIPHER_ERR_BUFFER_OVERFLOW;
        return CIPHER_ERR_BUFFER_OVERFLOW;
    }

    memset(ctx->out, 0, plaintextLength);

    uint8_t *block;
    block = ctx->iv;

    switch (cipher) {
        case AES:
            for (size_t n = 0; n < plaintextLength; n += AES_BLOCK_SIZE) {
                _bitwise_xor(block, (plaintext + n), AES_BLOCK_SIZE);
                _aes_encryptor(ctx->ctx, block);
                memcpy((ctx->out + n), ((struct _xcrypto_aes_cipher *)(ctx->ctx))->state, AES_BLOCK_SIZE);
                memcpy(block, (ctx->out + n), AES_BLOCK_SIZE);
            }
            ctx->outLen = plaintextLength;
            break;
        
        case DES:
            for (size_t n = 0; n < plaintextLength; n += DES_BLOCK_SIZE) {
                _bitwise_xor(block, (plaintext + n), DES_BLOCK_SIZE);
                _des_encryptor(((struct _xcrypto_des_cipher *)(ctx->ctx)), block);
                des_block(((struct _xcrypto_des_cipher *)(ctx->ctx)), (ctx->out + n));
                memcpy(block, (ctx->out + n), DES_BLOCK_SIZE);
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


static enum _xcrypto_cipher_op_state _CBC_decrypt(struct _xcrypto_generic_cipher *ctx, const uint8_t *ciphertext, size_t ciphertextLength) {
    Ciphers cipher = ctx->cipher;
    
    if (!ctx->iv) {
        ctx->error = CIPHER_ERR_MISSING_IV;
        return CIPHER_ERR_MISSING_IV;
    }

    if (ciphertextLength % CipherBlockSize[cipher] != 0) {
        ctx->error = CIPHER_ERR_INVALID_PLAINTEXT_SIZE;
        return CIPHER_ERR_INVALID_PLAINTEXT_SIZE;
    }
    
    if (ciphertextLength > ctx->maxOutLen) {
        ctx->error = CIPHER_ERR_BUFFER_OVERFLOW;
        return CIPHER_ERR_BUFFER_OVERFLOW;
    }

    memset(ctx->out, 0, ciphertextLength);

    uint8_t *block;
    block = ctx->iv;

    switch (ctx->cipher) {
        case AES:
            for (size_t n = 0; n < ciphertextLength; n += AES_BLOCK_SIZE) {
                _aes_decryptor(ctx->ctx, (ciphertext + n));
                memcpy((ctx->out + n), ((struct _xcrypto_aes_cipher *)(ctx->ctx))->state, AES_BLOCK_SIZE);
                _bitwise_xor((ctx->out + n), block, AES_BLOCK_SIZE);
                memcpy(block, (ciphertext + n), AES_BLOCK_SIZE);
            }
            ctx->outLen = ciphertextLength;
            break;
        
        case DES:
            for (size_t n = 0; n < ciphertextLength; n += DES_BLOCK_SIZE) {
                _des_decryptor(ctx->ctx, (ciphertext + n));
                des_block(((struct _xcrypto_des_cipher *)(ctx->ctx)), (ctx->out + n));
                _bitwise_xor((ctx->out + n), block, DES_BLOCK_SIZE);
                memcpy(block, (ciphertext + n), DES_BLOCK_SIZE);
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


static enum _xcrypto_cipher_op_state _CTR_encrypt(struct _xcrypto_generic_cipher *ctx, const uint8_t *plaintext, size_t plaintextLength) {
    Ciphers cipher = ctx->cipher;

    if (!ctx->iv) {
        ctx->error = CIPHER_ERR_MISSING_IV;
        return CIPHER_ERR_MISSING_IV;
    }

    if (plaintextLength > ctx->maxOutLen) {
        ctx->error = CIPHER_ERR_BUFFER_OVERFLOW;
        return CIPHER_ERR_BUFFER_OVERFLOW;
    }

    memset(ctx->out, 0, plaintextLength);

    uint8_t nonce[16];
    size_t nonceIdx;
    size_t counterSize;
    size_t n;

    nonceIdx = ctx->ivLen;
    counterSize = CipherBlockSize[ctx->cipher] - nonceIdx;
    memset(nonce, 0, 16);
    memcpy(nonce, ctx->iv, ctx->ivLen);

    switch (cipher) {
        case AES:
            for (n = 0; n < (plaintextLength - (plaintextLength % AES_BLOCK_SIZE)); n += AES_BLOCK_SIZE) {
                _aes_encryptor(ctx->ctx, nonce);
                memcpy((ctx->out + n), ((struct _xcrypto_aes_cipher *)(ctx->ctx))->state, AES_BLOCK_SIZE);
                _bitwise_xor((ctx->out + n), (plaintext + n), AES_BLOCK_SIZE);
                _inc_nonce(nonce + nonceIdx, counterSize);
            }

            if (plaintextLength % AES_BLOCK_SIZE != 0) {
                _aes_encryptor(ctx->ctx, nonce);
                memcpy((ctx->out + n), ((struct _xcrypto_aes_cipher *)(ctx->ctx))->state, (plaintextLength % AES_BLOCK_SIZE));
                _bitwise_xor((ctx->out + n), (plaintext + n), (plaintextLength % AES_BLOCK_SIZE));
                _inc_nonce(nonce + nonceIdx, counterSize);
            }

            ctx->outLen = plaintextLength;
            break;

        case DES:
            for (n = 0; n < (plaintextLength - (plaintextLength % DES_BLOCK_SIZE)); n += DES_BLOCK_SIZE) {
                _des_encryptor(ctx->ctx, nonce);
                des_block(ctx->ctx, (ctx->out + n));
                _bitwise_xor((ctx->out + n), (plaintext + n), DES_BLOCK_SIZE);
                _inc_nonce(nonce + nonceIdx, counterSize);
            }

            if (plaintextLength % DES_BLOCK_SIZE != 0) {
                _des_encryptor(ctx->ctx, nonce);
                des_block(ctx->ctx, (ctx->out + n));
                _bitwise_xor((ctx->out + n), (plaintext + n), (plaintextLength % DES_BLOCK_SIZE));
                _inc_nonce(nonce + nonceIdx, counterSize);
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


enum _xcrypto_cipher_op_state CipherEncrypt(struct _xcrypto_generic_cipher *ctx, uint8_t *plaintext, size_t plaintextLength) {
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

    if (!ctx->out) {
        ctx->error = CIPHER_ERR_MISSING_BUF;
        return CIPHER_ERR_MISSING_BUF;
    }
    
    enum _xcrypto_cipher_op_state state;
    
    switch(ctx->mode) {
        case ECB:
            if ((state = _ECB_encrypt(ctx, plaintext, plaintextLength)) != CIPHER_SUCCESS)
                return state;
            break;
        
        case CBC:
            if ((state = _CBC_encrypt(ctx, plaintext, plaintextLength)) != CIPHER_SUCCESS)
                return state;
            break;
        
        case CTR:
            if ((state = _CTR_encrypt(ctx, plaintext, plaintextLength)) != CIPHER_SUCCESS)
                return state;
            break;
        
        default:
            ctx->error = CIPHER_ERR_UNSUPPORTED_MODE;
            return CIPHER_ERR_UNSUPPORTED_MODE;
    }

    ctx->error = CIPHER_SUCCESS;
    return CIPHER_SUCCESS;
}


enum _xcrypto_cipher_op_state CipherDecrypt(struct _xcrypto_generic_cipher *ctx, uint8_t *ciphertext, size_t ciphertextLength) {
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

    if (!ctx->out) {
        ctx->error = CIPHER_ERR_MISSING_BUF;
        return CIPHER_ERR_MISSING_BUF;
    }
    
    enum _xcrypto_cipher_op_state state;

    switch(ctx->mode) {
        case ECB:
            if ((state = _ECB_decrypt(ctx, ciphertext, ciphertextLength)) != CIPHER_SUCCESS)
                return state;
            break;
        
        case CBC:
            if ((state = _CBC_decrypt(ctx, ciphertext, ciphertextLength)) != CIPHER_SUCCESS)
                return state;
            break;
        
        case CTR:
            if ((state = _CTR_encrypt(ctx, ciphertext, ciphertextLength)) != CIPHER_SUCCESS)
                return state;
            break;
        
        default:
            ctx->error = CIPHER_ERR_UNSUPPORTED_MODE;
            return CIPHER_ERR_UNSUPPORTED_MODE;
    }

    ctx->error = CIPHER_SUCCESS;
    return CIPHER_SUCCESS;
}


enum _xcrypto_cipher_op_state CipherFinalize(struct _xcrypto_generic_cipher *ctx) {
    if (!ctx)
        return CIPHER_ERR_NULL_PTR;

    ctx->out = NULL;
    ctx->outLen = 0;
    ctx->error = CIPHER_SUCCESS;
}


enum _xcrypto_cipher_op_state FreeCipher(struct _xcrypto_generic_cipher *ctx) {
    if (!ctx)
        return CIPHER_ERR_NULL_PTR;

    if (ctx->ctx)
        free(ctx->ctx);
    
    free(ctx);

    ctx->error = CIPHER_SUCCESS;
    return CIPHER_SUCCESS;
}


enum _xcrypto_cipher_op_state CipherReset(struct _xcrypto_generic_cipher *ctx, CipherResetMode mode) {
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


enum _xcrypto_cipher_op_state CipherGetError(struct _xcrypto_generic_cipher *ctx) {
    if (!ctx)
        return CIPHER_ERR_NULL_PTR;

    return ctx->error;
}


const uint8_t *CipherGetErrorString[] = {
    [CIPHER_SUCCESS] = "Success",
    [CIPHER_ERR_INVALID_ARG] = "Invalid argument",
    [CIPHER_ERR_NULL_PTR] = "Parameter with null pointer",
    [CIPHER_ERR_UNSUPPORTED_ALGO] = "Algorithm not supported or non-existent",
    [CIPHER_ERR_INVALID_KEY] = "Invalid key or incompatible key length",
    [CIPHER_ERR_UNSUPPORTED_MODE] = "Invalid or non-existent mode",
    [CIPHER_ERR_MEM_ALLOC] = "Error allocating memory to heap",
    [CIPHER_ERR_MISSING_ALGO] = "Algorithm not set ( use CipherSetAlgorithm )",
    [CIPHER_ERR_MISSING_BUF] = "Missing buffer for encryption or decryption ( use CipherSetBuffer )",
    [CIPHER_ERR_INVALID_BLOCK_SIZE] = "Invalid block size",
    [CIPHER_ERR_INVALID_PLAINTEXT_SIZE] = "Invalid plaintext size (try with padding)",
    [CIPHER_ERR_INVALID_CIPHERTEXT_SIZE] = "Invalid ciphertext size",
    [CIPHER_ERR_MISSING_IV] = "Required IV missing ( try CipherSetIV )",
    [CIPHER_ERR_BUFFER_OVERFLOW] = "The buffer size is too small"
};


const uint32_t CipherBlockSize[] = {
    [CIPHER_NOT_SET] = 0,
    [AES] = 16,
    [DES] = 8
};