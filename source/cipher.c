#include "xcrypto/cipher.h"
#include "xcrypto/aes.h"
#include "xcrypto/des.h"
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
        case CIPHER_AES:
        case CIPHER_DES:
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
        case CIPHER_AES:
            if (keyLength != 16 && keyLength != 24 && keyLength != 32) {
                ctx->error = CIPHER_ERR_INVALID_KEY;
                return CIPHER_ERR_INVALID_KEY;
            }

            ctx->ctx = AesInit(key, keyLength);
            break;
        
        case CIPHER_DES:
            if (keyLength != 8) {
                ctx->error = CIPHER_ERR_INVALID_KEY;
                return CIPHER_ERR_INVALID_KEY;
            }

            ctx->ctx = DesInit(key);
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
        case CIPHER_MODE_ECB:
        case CIPHER_MODE_CBC:
        case CIPHER_MODE_CTR:
        case CIPHER_MODE_OFB:
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


static enum _xcrypto_cipher_op_state _CIPHER_MODE_ECB_encrypt(struct _xcrypto_generic_cipher *ctx, const uint8_t *plaintext, size_t plaintextLength) {    
    if (plaintextLength % CipherBlockSize[ctx->cipher] != 0) {
        ctx->error = CIPHER_ERR_INVALID_PLAINTEXT_SIZE;
        return CIPHER_ERR_INVALID_PLAINTEXT_SIZE;
    }

    if (plaintextLength > ctx->maxOutLen) {
        ctx->error = CIPHER_ERR_BUFFER_OVERFLOW;
        return CIPHER_ERR_BUFFER_OVERFLOW;
    }
    
    switch (ctx->cipher) {
        case CIPHER_AES:            
            for (size_t n = 0; n < plaintextLength; n += AES_BLOCK_SIZE) {
                AesEncryptor(ctx->ctx, plaintext + n);
                AesGetBlock(ctx->ctx, ctx->out + n);
            }
            ctx->outLen = plaintextLength;
            break;
        
        case CIPHER_DES:
            for (size_t n = 0; n < plaintextLength; n += DES_BLOCK_SIZE) {
                DesEncryptor(ctx->ctx, plaintext + n);
                DesGetBlock(ctx->ctx, ctx->out + n);
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


static enum _xcrypto_cipher_op_state _CIPHER_MODE_ECB_decrypt(struct _xcrypto_generic_cipher *ctx, const uint8_t *ciphertext, size_t ciphertextLength) {
    Ciphers cipher = ctx->cipher;

    if (ciphertextLength % CipherBlockSize[cipher] != 0) {
        ctx->error = CIPHER_ERR_INVALID_CIPHERTEXT_SIZE;
        return CIPHER_ERR_INVALID_CIPHERTEXT_SIZE;
    }

    if (ciphertextLength > ctx->maxOutLen) {
        ctx->error = CIPHER_ERR_BUFFER_OVERFLOW;
        return CIPHER_ERR_BUFFER_OVERFLOW;
    }
    
    switch (cipher) {
        case CIPHER_AES:
            for (size_t n = 0; n < ciphertextLength; n += AES_BLOCK_SIZE) {
                AesDecryptor(ctx->ctx, (ciphertext + n));
                AesGetBlock(ctx->ctx, ctx->out + n);
            }
            ctx->outLen = ciphertextLength;
            break;
        
        case CIPHER_DES:
            for (size_t n = 0; n < ciphertextLength; n += DES_BLOCK_SIZE) {
                DesDecryptor(ctx->ctx, (ciphertext + n));
                DesGetBlock(((struct _xcrypto_des_cipher *)(ctx->ctx)), (ctx->out + n));
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


static enum _xcrypto_cipher_op_state _CIPHER_MODE_CBC_encrypt(struct _xcrypto_generic_cipher *ctx, const uint8_t *plaintext, size_t plaintextLength) {
    Ciphers cipher = ctx->cipher;
    
    if (!ctx->iv) {
        ctx->error = CIPHER_ERR_MISSING_IV;
        return CIPHER_ERR_MISSING_IV;
    }

    if (ctx->ivLen != CipherBlockSize[cipher]) {
        ctx->error = CIPHER_ERR_INVALID_IV_SIZE;
        return CIPHER_ERR_INVALID_IV_SIZE;
    }

    if (plaintextLength % CipherBlockSize[cipher] != 0) {
        ctx->error = CIPHER_ERR_INVALID_CIPHERTEXT_SIZE;
        return CIPHER_ERR_INVALID_CIPHERTEXT_SIZE;
    }

    if (plaintextLength > ctx->maxOutLen) {
        ctx->error = CIPHER_ERR_BUFFER_OVERFLOW;
        return CIPHER_ERR_BUFFER_OVERFLOW;
    }

    uint8_t *block;
    block = ctx->iv;

    switch (cipher) {
        case CIPHER_AES:
            for (size_t n = 0; n < plaintextLength; n += AES_BLOCK_SIZE) {
                _bitwise_xor(block, (plaintext + n), AES_BLOCK_SIZE);
                AesEncryptor(ctx->ctx, block);
                AesGetBlock(ctx->ctx, ctx->out + n);
                memcpy(block, (ctx->out + n), AES_BLOCK_SIZE);
            }
            ctx->outLen = plaintextLength;
            break;
        
        case CIPHER_DES:
            for (size_t n = 0; n < plaintextLength; n += DES_BLOCK_SIZE) {
                _bitwise_xor(block, (plaintext + n), DES_BLOCK_SIZE);
                DesEncryptor(((struct _xcrypto_des_cipher *)(ctx->ctx)), block);
                DesGetBlock(((struct _xcrypto_des_cipher *)(ctx->ctx)), (ctx->out + n));
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


static enum _xcrypto_cipher_op_state _CIPHER_MODE_CBC_decrypt(struct _xcrypto_generic_cipher *ctx, const uint8_t *ciphertext, size_t ciphertextLength) {
    Ciphers cipher = ctx->cipher;
    
    if (!ctx->iv) {
        ctx->error = CIPHER_ERR_MISSING_IV;
        return CIPHER_ERR_MISSING_IV;
    }

    if (ctx->ivLen != CipherBlockSize[cipher]) {
        ctx->error = CIPHER_ERR_INVALID_IV_SIZE;
        return CIPHER_ERR_INVALID_IV_SIZE;
    }

    if (ciphertextLength % CipherBlockSize[cipher] != 0) {
        ctx->error = CIPHER_ERR_INVALID_PLAINTEXT_SIZE;
        return CIPHER_ERR_INVALID_PLAINTEXT_SIZE;
    }
    
    if (ciphertextLength > ctx->maxOutLen) {
        ctx->error = CIPHER_ERR_BUFFER_OVERFLOW;
        return CIPHER_ERR_BUFFER_OVERFLOW;
    }

    uint8_t *block;
    block = ctx->iv;

    switch (ctx->cipher) {
        case CIPHER_AES:
            for (size_t n = 0; n < ciphertextLength; n += AES_BLOCK_SIZE) {
                AesDecryptor(ctx->ctx, (ciphertext + n));
                AesGetBlock(ctx->ctx, ctx->out + n);
                _bitwise_xor((ctx->out + n), block, AES_BLOCK_SIZE);
                memcpy(block, (ciphertext + n), AES_BLOCK_SIZE);
            }
            ctx->outLen = ciphertextLength;
            break;
        
        case CIPHER_DES:
            for (size_t n = 0; n < ciphertextLength; n += DES_BLOCK_SIZE) {
                DesDecryptor(ctx->ctx, (ciphertext + n));
                DesGetBlock(((struct _xcrypto_des_cipher *)(ctx->ctx)), (ctx->out + n));
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


static enum _xcrypto_cipher_op_state _CIPHER_MODE_CTR_encrypt(struct _xcrypto_generic_cipher *ctx, const uint8_t *plaintext, size_t plaintextLength) {
    Ciphers cipher = ctx->cipher;

    if (!ctx->iv) {
        ctx->error = CIPHER_ERR_MISSING_IV;
        return CIPHER_ERR_MISSING_IV;
    }

    if (ctx->ivLen > CipherBlockSize[cipher]) {
        ctx->error = CIPHER_ERR_INVALID_IV_SIZE;
        return CIPHER_ERR_INVALID_IV_SIZE;
    }

    if (plaintextLength > ctx->maxOutLen) {
        ctx->error = CIPHER_ERR_BUFFER_OVERFLOW;
        return CIPHER_ERR_BUFFER_OVERFLOW;
    }

    uint8_t nonce[16];
    uint8_t tmp[16];
    size_t nonceIdx;
    size_t counterSize;
    size_t n;

    if ((nonceIdx = ctx->ivLen) == CipherBlockSize[cipher])
        counterSize = CipherBlockSize[cipher];
    else
        counterSize = CipherBlockSize[cipher] - nonceIdx;
    
    memset(nonce, 0, CipherBlockSize[cipher]);
    memcpy(nonce, ctx->iv, ctx->ivLen);

    switch (cipher) {
        case CIPHER_AES:
            for (n = 0; n < (plaintextLength - (plaintextLength % AES_BLOCK_SIZE)); n += AES_BLOCK_SIZE) {
                AesEncryptor(ctx->ctx, nonce);
                AesGetBlock(ctx->ctx, ctx->out + n);
                _bitwise_xor((ctx->out + n), (plaintext + n), AES_BLOCK_SIZE);
                _inc_nonce(nonce + nonceIdx, counterSize);
            }

            if (plaintextLength % AES_BLOCK_SIZE != 0) {
                AesEncryptor(ctx->ctx, nonce);
                AesGetBlock(ctx->ctx, tmp);
                memcpy(ctx->out + n, tmp, (plaintextLength % AES_BLOCK_SIZE));
                _bitwise_xor((ctx->out + n), (plaintext + n), (plaintextLength % AES_BLOCK_SIZE));
                _inc_nonce(nonce + nonceIdx, counterSize);
            }

            ctx->outLen = plaintextLength;
            break;

        case CIPHER_DES:
            for (n = 0; n < (plaintextLength - (plaintextLength % DES_BLOCK_SIZE)); n += DES_BLOCK_SIZE) {
                DesEncryptor(ctx->ctx, nonce);
                DesGetBlock(ctx->ctx, (ctx->out + n));
                _bitwise_xor((ctx->out + n), (plaintext + n), DES_BLOCK_SIZE);
                _inc_nonce(nonce + nonceIdx, counterSize);
            }

            if (plaintextLength % DES_BLOCK_SIZE != 0) {
                DesEncryptor(ctx->ctx, nonce);
                DesGetBlock(ctx->ctx, tmp);
                memcpy((ctx->out + n), tmp, (plaintextLength % DES_BLOCK_SIZE));
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


static enum _xcrypto_cipher_op_state _CIPHER_MODE_OFB_encrypt(struct _xcrypto_generic_cipher *ctx, const uint8_t *plaintext, size_t plaintextLength) {
    Ciphers cipher = ctx->cipher;

    if (!ctx->iv) {
        ctx->error = CIPHER_ERR_MISSING_IV;
        return CIPHER_ERR_MISSING_IV;
    }

    if (ctx->ivLen != CipherBlockSize[cipher]) {
        ctx->error = CIPHER_ERR_INVALID_IV_SIZE;
        return CIPHER_ERR_INVALID_IV_SIZE;
    }

    if (plaintextLength > ctx->maxOutLen) {
        ctx->error = CIPHER_ERR_BUFFER_OVERFLOW;
        return CIPHER_ERR_BUFFER_OVERFLOW;
    }

    uint8_t nonce[16];
    uint8_t tmp[16];
    size_t n;

    memcpy(nonce, ctx->iv, CipherBlockSize[cipher]);

    switch (cipher) {
        case CIPHER_AES:
            for (n = 0; n < (plaintextLength - (plaintextLength % AES_BLOCK_SIZE)); n += AES_BLOCK_SIZE) {
                AesEncryptor(ctx->ctx, nonce);
                AesGetBlock(ctx->ctx, nonce);
                memcpy(ctx->out + n, nonce, AES_BLOCK_SIZE);
                _bitwise_xor((ctx->out + n), (plaintext + n), AES_BLOCK_SIZE);
            }

            if (plaintextLength % AES_BLOCK_SIZE != 0) {
                AesEncryptor(ctx->ctx, nonce);
                AesGetBlock(ctx->ctx, nonce);
                memcpy(ctx->out + n, nonce, (plaintextLength % AES_BLOCK_SIZE));
                _bitwise_xor((ctx->out + n), (plaintext + n), (plaintextLength % AES_BLOCK_SIZE));
            }

            ctx->outLen = plaintextLength;
            break;

        case CIPHER_DES:
            for (n = 0; n < (plaintextLength - (plaintextLength % DES_BLOCK_SIZE)); n += DES_BLOCK_SIZE) {
                DesEncryptor(ctx->ctx, nonce);
                DesGetBlock(ctx->ctx, nonce);
                memcpy(ctx->out + n, nonce, DES_BLOCK_SIZE);
                _bitwise_xor((ctx->out + n), (plaintext + n), DES_BLOCK_SIZE);
            }

            if (plaintextLength % DES_BLOCK_SIZE != 0) {
                DesEncryptor(ctx->ctx, nonce);
                DesGetBlock(ctx->ctx, tmp);
                memcpy((ctx->out + n), tmp, (plaintextLength % DES_BLOCK_SIZE));
                _bitwise_xor((ctx->out + n), (plaintext + n), (plaintextLength % DES_BLOCK_SIZE));
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
        case CIPHER_MODE_ECB:
            if ((state = _CIPHER_MODE_ECB_encrypt(ctx, plaintext, plaintextLength)) != CIPHER_SUCCESS)
                return state;
            break;
        
        case CIPHER_MODE_CBC:
            if ((state = _CIPHER_MODE_CBC_encrypt(ctx, plaintext, plaintextLength)) != CIPHER_SUCCESS)
                return state;
            break;
        
        case CIPHER_MODE_CTR:
            if ((state = _CIPHER_MODE_CTR_encrypt(ctx, plaintext, plaintextLength)) != CIPHER_SUCCESS)
                return state;
            break;
        
        case CIPHER_MODE_OFB:
            if ((state = _CIPHER_MODE_OFB_encrypt(ctx, plaintext, plaintextLength)) != CIPHER_SUCCESS)
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
        case CIPHER_MODE_ECB:
            if ((state = _CIPHER_MODE_ECB_decrypt(ctx, ciphertext, ciphertextLength)) != CIPHER_SUCCESS)
                return state;
            break;
        
        case CIPHER_MODE_CBC:
            if ((state = _CIPHER_MODE_CBC_decrypt(ctx, ciphertext, ciphertextLength)) != CIPHER_SUCCESS)
                return state;
            break;
        
        case CIPHER_MODE_CTR:
            if ((state = _CIPHER_MODE_CTR_encrypt(ctx, ciphertext, ciphertextLength)) != CIPHER_SUCCESS)
                return state;
            break;

        case CIPHER_MODE_OFB:
            if ((state = _CIPHER_MODE_OFB_encrypt(ctx, ciphertext, ciphertextLength)) != CIPHER_SUCCESS)
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
    [CIPHER_ERR_NOT_IMPLEMENTED] = "Functionality not yet implemented",
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
    [CIPHER_ERR_INVALID_IV_SIZE] = "The size of the IV does not match the AES block size.",
    [CIPHER_ERR_BUFFER_OVERFLOW] = "The buffer size is too small"
};


const uint32_t CipherBlockSize[] = {
    [CIPHER_NOT_SET] = 0,
    [CIPHER_AES] = 16,
    [CIPHER_DES] = 8
};