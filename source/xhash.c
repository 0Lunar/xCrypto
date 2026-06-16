#include "xhash.h"
#include "xmd5.h"
#include "xsha0.h"
#include "xsha1.h"
#include "xsha224.h"
#include "xsha256.h"
#include "xsha384.h"
#include "xsha512.h"
#include <stdlib.h>
#include <memory.h>


struct _xcrypto_hash_ctx *NewHash() {
    struct _xcrypto_hash_ctx *ctx;

    if ((ctx = malloc(sizeof(struct _xcrypto_hash_ctx))) == NULL)
        return NULL;


    memset(ctx, 0, sizeof(struct _xcrypto_hash_ctx));
    ctx->algorithm = XCRYPTO_HASH_NOT_SET;
    ctx->error = HASH_SUCCESS;

    return ctx;
}


enum _xcrypto_hash_op_state HashSetAlgorithm(struct _xcrypto_hash_ctx *ctx, enum _xcrypto_hash_algo algorithm) {
    if (!ctx)
        return HASH_ERR_NULL_PTR;

    if (ctx->ctx) {
        free(ctx->ctx);
        ctx->finalized = 0;
    }
    
    switch (algorithm) {
        case XCRYPTO_HASH_NOT_SET:
            break;

        case XCRYPTO_MD5:
            ctx->ctx = XMD5_Init();
            break;

        case XCRYPTO_SHA0:
            ctx->ctx = XSHA0_Init();
            break;

        case XCRYPTO_SHA1:
            ctx->ctx = XSHA1_Init();
            break;

        case XCRYPTO_SHA224:
            ctx->ctx = XSHA224_Init();
            break;
        
        case XCRYPTO_SHA256:
            ctx->ctx = XSHA256_Init();
            break;
        
        case XCRYPTO_SHA384:
            ctx->ctx = XSHA384_Init();
            break;

        case XCRYPTO_SHA512:
            ctx->ctx = XSHA512_Init();
            break;
        
        default:
            ctx->error = HASH_ERR_UNSUPPORTED_ALGO;
            return HASH_ERR_UNSUPPORTED_ALGO;
    }

    ctx->algorithm = algorithm;
    ctx->error = HASH_SUCCESS;
    return HASH_SUCCESS;
}


enum _xcrypto_hash_op_state HashUpdate(struct _xcrypto_hash_ctx *ctx, const uint8_t *buf, size_t bufSize) {
    if (!ctx)
        return HASH_ERR_NULL_PTR;

    if (ctx->finalized) {
        ctx->error = HASH_ERR_FINALIZED;
        return HASH_ERR_FINALIZED;
    }
    
    if (!buf) {
        ctx->error = HASH_ERR_NULL_PTR;
        return HASH_ERR_NULL_PTR;
    }

    if (bufSize == 0 || ctx->algorithm == XCRYPTO_HASH_NOT_SET) {
        ctx->error = HASH_SUCCESS;
        return HASH_SUCCESS;
    }

    switch (ctx->algorithm) {
        case XCRYPTO_MD5:
            XMD5_Update(ctx->ctx, buf, bufSize);
            break;
        
        case XCRYPTO_SHA0:
            XSHA0_Update(ctx->ctx, buf, bufSize);
            break;

        case XCRYPTO_SHA1:
            XSHA1_Update(ctx->ctx, buf, bufSize);
            break;

        case XCRYPTO_SHA224:
            XSHA224_Update(ctx->ctx, buf, bufSize);
            break;
        
        case XCRYPTO_SHA256:
            XSHA256_Update(ctx->ctx, buf, bufSize);
            break;
        
        case XCRYPTO_SHA384:
            XSHA384_Update(ctx->ctx, buf, bufSize);
            break;
        
        case XCRYPTO_SHA512:
            XSHA512_Update(ctx->ctx, buf, bufSize);
            break;
        
        default:
            ctx->error = HASH_ERR_UNSUPPORTED_ALGO;
            return HASH_ERR_UNSUPPORTED_ALGO;
    }

    ctx->error = HASH_SUCCESS;
    return HASH_SUCCESS;
}


enum _xcrypto_hash_op_state HashFinalize(struct _xcrypto_hash_ctx *ctx, uint8_t *buf, size_t bufSize) {
    if (!ctx)
        return HASH_ERR_NULL_PTR;

    if (ctx->finalized) {
        ctx->error = HASH_ERR_FINALIZED;
        return HASH_ERR_FINALIZED;
    }
    
    if (!buf) {
        ctx->error = HASH_ERR_MISSING_BUF;
        return HASH_ERR_MISSING_BUF;
    }

    if (bufSize < HashDigestSize[ctx->algorithm]) {
        ctx->error = HASH_ERR_BUFFER_OVERFLOW;
        return HASH_ERR_BUFFER_OVERFLOW;
    }

    if (ctx->algorithm == XCRYPTO_HASH_NOT_SET) {
        ctx->error = HASH_SUCCESS;
        return HASH_SUCCESS;
    }

    switch (ctx->algorithm) {
        case XCRYPTO_MD5:
            XMD5_Finalize(ctx->ctx, buf);
            break;
        
        case XCRYPTO_SHA0:
            XSHA0_Finalize(ctx->ctx, buf);
            break;
        
        case XCRYPTO_SHA1:
            XSHA1_Finalize(ctx->ctx, buf);
            break;

        case XCRYPTO_SHA224:
            XSHA224_Finalize(ctx->ctx, buf);
            break;
        
        case XCRYPTO_SHA256:
            XSHA256_Finalize(ctx->ctx, buf);
            break;

        case XCRYPTO_SHA384:
            XSHA384_Finalize(ctx->ctx, buf);
            break;
        
        case XCRYPTO_SHA512:
            XSHA512_Finalize(ctx->ctx, buf);
            break;
        
        default:
            ctx->error = HASH_ERR_UNSUPPORTED_ALGO;
            return HASH_ERR_UNSUPPORTED_ALGO;
    }

    ctx->finalized = 1;
    ctx->error = HASH_SUCCESS;
    return HASH_SUCCESS;
}


enum _xcrypto_hash_op_state HashReset(struct _xcrypto_hash_ctx *ctx) {
    if (!ctx)
        return HASH_ERR_NULL_PTR;

    if (ctx->ctx) {
        switch (ctx->algorithm) {
            case XCRYPTO_HASH_NOT_SET:
                break;

            case XCRYPTO_MD5:
                XMD5_Reset(ctx->ctx);
                break;
            
            case XCRYPTO_SHA0:
                XSHA0_Reset(ctx->ctx);
                break;

            case XCRYPTO_SHA1:
                XSHA1_Reset(ctx->ctx);
                break;

            case XCRYPTO_SHA224:
                XSHA224_Reset(ctx->ctx);
                break; 
                
            case XCRYPTO_SHA256:
                XSHA256_Reset(ctx->ctx);
                break;
            
            case XCRYPTO_SHA384:
                XSHA384_Reset(ctx->ctx);
                break;
            
            case XCRYPTO_SHA512:
                XSHA512_Reset(ctx->ctx);
                break;
        
            default:
                ctx->error = HASH_ERR_UNSUPPORTED_ALGO;
                return HASH_ERR_UNSUPPORTED_ALGO;
                break;
        }
    }

    ctx->algorithm = XCRYPTO_HASH_NOT_SET;
    ctx->finalized = 0;
    ctx->error = HASH_SUCCESS;
    return HASH_SUCCESS;
}


enum _xcrypto_hash_op_state HashFree(struct _xcrypto_hash_ctx *ctx) {
    if (!ctx)
        return HASH_ERR_NULL_PTR;
    
    if (ctx->ctx)
        free(ctx->ctx);
    
    free(ctx);

    return HASH_SUCCESS;
}


enum _xcrypto_hash_op_state HashOneshot(enum _xcrypto_hash_algo algorithm, const uint8_t *plaintext, size_t plaintextSize, uint8_t *digest, size_t digestSize) {
    if (!plaintext || !digest)
        return HASH_ERR_NULL_PTR;
    
    if (plaintextSize == 0)
        return HASH_SUCCESS;

    if (digestSize < HashDigestSize[algorithm])
        return HASH_ERR_BUFFER_OVERFLOW;
    
    void *ctx;
    uint32_t error;

    switch (algorithm) {
        case XCRYPTO_MD5:
            if ((ctx = XMD5_Init()) == NULL)
                return HASH_ERR_MEM_ALLOC;
            
            if (XMD5_Update(ctx, plaintext, plaintextSize) != MD5_SUCCESS)
                return HASH_ERR_ONESHOT;
            
            error = XMD5_Finalize(ctx, digest);
            break;

        case XCRYPTO_SHA0:
            if ((ctx = XSHA0_Init()) == NULL)
                return HASH_ERR_MEM_ALLOC;
            
            if (XSHA0_Update(ctx, plaintext, plaintextSize) != SHA0_SUCCESS)
                return HASH_ERR_ONESHOT;
            
            error = XSHA0_Finalize(ctx, digest);
            break;
        
        case XCRYPTO_SHA1:
            if ((ctx = XSHA1_Init()) == NULL)
                return HASH_ERR_MEM_ALLOC;
            
            if (XSHA1_Update(ctx, plaintext, plaintextSize) != SHA1_SUCCESS)
                return HASH_ERR_ONESHOT;
            
            error = XSHA1_Finalize(ctx, digest);
            break;

        case XCRYPTO_SHA224:
            if ((ctx = XSHA224_Init()) == NULL)
                return HASH_ERR_MEM_ALLOC;
            
            if (XSHA224_Update(ctx, plaintext, plaintextSize) != SHA1_SUCCESS)
                return HASH_ERR_ONESHOT;
            
            error = XSHA224_Finalize(ctx, digest);
            break;
        
        case XCRYPTO_SHA256:
            if ((ctx = XSHA256_Init()) == NULL)
                return HASH_ERR_MEM_ALLOC;
            
            if (XSHA256_Update(ctx, plaintext, plaintextSize) != SHA1_SUCCESS)
                return HASH_ERR_ONESHOT;
            
            error = XSHA256_Finalize(ctx, digest);
            break;

        case XCRYPTO_SHA384:
            if ((ctx = XSHA384_Init()) == NULL)
                return HASH_ERR_MEM_ALLOC;
            
            if (XSHA384_Update(ctx, plaintext, plaintextSize) != SHA1_SUCCESS)
                return HASH_ERR_ONESHOT;
            
            error = XSHA384_Finalize(ctx, digest);
            break;

        case XCRYPTO_SHA512:
            if ((ctx = XSHA512_Init()) == NULL)
                return HASH_ERR_MEM_ALLOC;
            
            if (XSHA512_Update(ctx, plaintext, plaintextSize) != SHA1_SUCCESS)
                return HASH_ERR_ONESHOT;
            
            error = XSHA512_Finalize(ctx, digest);
            break;
        
        default:
            return HASH_ERR_UNSUPPORTED_ALGO;
    }

    free(ctx);

    if (error != 0)        
        return HASH_ERR_ONESHOT;
    
    return HASH_SUCCESS;
}


const uint8_t *HashGetErrorString[] = {
    [HASH_SUCCESS] = "Success",
    [HASH_ERR_INVALID_ARG] = "Invalid argument",
    [HASH_ERR_NULL_PTR] = "Parameter with null pointer",
    [HASH_ERR_UNSUPPORTED_ALGO] = "Algorithm not supported or non-existent",
    [HASH_ERR_MEM_ALLOC] = "Error allocating memory to heap",
    [HASH_ERR_MISSING_ALGO] = "Algorithm not set ( try HashSetAlgorithm )",
    [HASH_ERR_MISSING_BUF] = "Missing buffer for hashing ( try HashSetBuffer )",
    [HASH_ERR_BUFFER_OVERFLOW] = "The buffer size is too small",
    [HASH_ERR_ONESHOT] = "Generic error on hash oneshot",
    [HASH_ERR_FINALIZED] = "You are trying to use a hash that is already finalized ( use HashReset )"
};


const size_t HashDigestSize[] = {
    [XCRYPTO_HASH_NOT_SET] = 0,
    [XCRYPTO_MD5] = 16,
    [XCRYPTO_SHA0] = 20,
    [XCRYPTO_SHA1] = 20,
    [XCRYPTO_SHA224] = 28,
    [XCRYPTO_SHA256] = 32,
    [XCRYPTO_SHA384] = 48,
    [XCRYPTO_SHA512] = 64,
};