#include "xhash.h"
#include "xmd5.h"
#include "xsha0.h"
#include "xsha1.h"
#include <stdlib.h>
#include <memory.h>


struct _xcrypto_hash_ctx *NewHash() {
    struct _xcrypto_hash_ctx *ctx;

    if ((ctx = malloc(sizeof(struct _xcrypto_hash_ctx))) == NULL)
        return NULL;


    memset(ctx, 0, sizeof(struct _xcrypto_hash_ctx));
    ctx->error = HASH_SUCCESS;

    return ctx;
}


enum _xcrypto_hash_op_state HashSetAlgorithm(struct _xcrypto_hash_ctx *ctx, enum _xcrypto_hash_algo algorithm) {
    if (!ctx)
        return HASH_ERR_NULL_PTR;
    
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
        
        default:
            ctx->error = HASH_ERR_INVALID_ARG;
            return HASH_ERR_INVALID_ARG;
    }

    ctx->error = HASH_SUCCESS;
    return HASH_SUCCESS;
}


enum _xcrypto_hash_op_state HashFinalize(struct _xcrypto_hash_ctx *ctx, uint8_t *buf, size_t bufSize) {
    if (!ctx)
        return HASH_ERR_NULL_PTR;
    
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
        
        default:
            ctx->error = HASH_ERR_UNSUPPORTED_ALGO;
            return HASH_ERR_UNSUPPORTED_ALGO;
    }

    ctx->error = HASH_SUCCESS;
    return HASH_SUCCESS;
}


enum _xcrypto_hash_op_state HashReset(struct _xcrypto_hash_ctx *ctx, enum _xcrypto_hash_reset_mode mode) {
    if (!ctx)
        return HASH_ERR_NULL_PTR;

    ctx->algorithm = XCRYPTO_HASH_NOT_SET;

    if (mode = HASH_FULL_RESET && ctx->ctx)
        free(ctx->ctx);

    ctx->error = HASH_SUCCESS;
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
    [HASH_ERR_BUFFER_OVERFLOW] = "The buffer size is too small"
};


const size_t HashDigestSize[] = {
    [XCRYPTO_HASH_NOT_SET] = 0,
    [XCRYPTO_MD5] = MD5_DIGEST_LEN,
    [XCRYPTO_SHA0] = SHA0_DIGEST_LEN,
    [XCRYPTO_SHA1] = SHA1_DIGEST_LEN
};