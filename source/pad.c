#include "xcrypto/pad.h"


static enum _xcrypto_padding_errors __pkcs7_pad( const uint8_t *msg, size_t msgLen, uint8_t *padBuf, uint8_t padSize, size_t *newMsgLen ) {
    size_t paddedLen;
    uint8_t padch;

    padch = (padSize - (msgLen % padSize));
    paddedLen = msgLen + padch;

    if (newMsgLen)
        *newMsgLen = paddedLen;
    
    memcpy(padBuf, msg, msgLen);

    for (size_t n = msgLen; n < paddedLen; n++)
        padBuf[n] = padch;
    
    return PAD_SUCCESS;
}


static enum _xcrypto_padding_errors __pkcs7_unpad( const uint8_t *padded, size_t paddedLen, uint8_t *unpadBuf, uint8_t padSize, size_t *newMsgLen ) {
    size_t msgLen;
    uint8_t padch;

    padch = padded[paddedLen - 1];

    if (padch > padSize)
        return PAD_ERR_INVALID_SIZE;

    msgLen = paddedLen - (size_t)padch;

    if (newMsgLen)
        *newMsgLen = msgLen;

    for ( size_t n = paddedLen - 2; n >= msgLen; n-- ) {
        if (padded[n] != padch)
            return PAD_ERR_INVALID_SEQ;
    }

    memcpy(unpadBuf, padded, msgLen);
    return PAD_SUCCESS;
}


static enum _xcrypto_padding_errors __x923_pad( const uint8_t *msg, size_t msgLen, uint8_t *padBuf, uint8_t padSize, size_t *newMsgLen ) {
    size_t paddedLen;
    uint8_t padch;

    padch = (padSize - (msgLen % padSize));
    paddedLen = msgLen + padch;

    if (newMsgLen)
        *newMsgLen = paddedLen;
    
    memcpy(padBuf, msg, msgLen);
    
    for ( size_t n = msgLen; n < paddedLen - 1; n++ )
        padBuf[n] = 0;

    padBuf[paddedLen - 1] = padch;
    return PAD_SUCCESS;
}


static enum _xcrypto_padding_errors __x923_unpad( const uint8_t *padded, size_t paddedLen, uint8_t *unpadBuf, uint8_t padSize, size_t *newMsgLen ) {
    size_t msgLen;
    uint8_t padch;

    padch = padded[paddedLen - 1];

    if (padch > padSize)
        return PAD_ERR_INVALID_SIZE;

    msgLen = paddedLen - (size_t)padch;

    if (newMsgLen)
        *newMsgLen = msgLen;

    for ( size_t n = paddedLen - 2; n >= msgLen; n-- ) {
        if (padded[n] != 0)
            return PAD_ERR_INVALID_SEQ;
    }

    memcpy(unpadBuf, padded, msgLen);
    return PAD_SUCCESS;
}


enum _xcrypto_padding_errors Padder(enum _xcrypto_padding_types padding, const uint8_t *msg, size_t msgLen, uint8_t *padBuf, uint8_t padSize, size_t *newMsgLen) {
    switch (padding) {
        case PKCS7:
            return __pkcs7_pad(msg, msgLen, padBuf, padSize, newMsgLen);
        
        case X923:
            return __x923_pad(msg, msgLen, padBuf, padSize, newMsgLen);
        
        default:
            return PAD_ERR_UNSUPPORTED_ALGO;
            break;
    }
}


enum _xcrypto_padding_errors Unpadder(enum _xcrypto_padding_types padding, uint8_t *padded, size_t paddedLen, uint8_t *unpadBuf, uint8_t padSize, size_t *newMsgLen) {
    switch (padding) {
    case PKCS7:
        return __pkcs7_unpad(padded, paddedLen, unpadBuf, padSize, newMsgLen);
    
    case X923:
        return __x923_unpad(padded, paddedLen, unpadBuf, padSize, newMsgLen);
    
    default:
        return PAD_ERR_UNSUPPORTED_ALGO;
        break;
    }
}


const uint8_t *PadGetErrorString[] = {
    [PAD_SUCCESS] = "Success",
    [PAD_ERR_NULL_PTR] = "Parameter with null pointer",
    [PAD_ERR_UNSUPPORTED_ALGO] = "Algorithm not supported or non-existent",
    [PAD_ERR_INVALID_SIZE] = "The padding size does not match",
    [PAD_ERR_INVALID_SEQ] = "Invalid padding"
};