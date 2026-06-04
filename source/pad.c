#include "pad.h"


static uint8_t *__pkcs7_pad( const uint8_t *msg, const size_t msgLen, const uint8_t padSize, size_t *newMsgLen ) {
    uint8_t *paddedMsg;
    size_t paddedLen;
    uint8_t padch;

    padch = (padSize - (msgLen % padSize));
    paddedLen = msgLen + padch;
    *newMsgLen = paddedLen;

    if ( (paddedMsg = malloc(paddedLen)) == NULL )
        return NULL;
    
    memcpy(paddedMsg, msg, msgLen);

    for (size_t n = msgLen; n < paddedLen; n++)
        paddedMsg[n] = padch;

    return paddedMsg;
}


static uint8_t *__pkcs7_unpad( const uint8_t *padded, const size_t paddedLen, const uint8_t padSize, size_t *newMsgLen ) {
    uint8_t *msg;
    size_t msgLen;
    uint8_t padch;

    padch = padded[paddedLen - 1];

    if (padch > padSize)
        return NULL;

    msgLen = paddedLen - (size_t)padch;
    *newMsgLen = msgLen;

    for ( size_t n = paddedLen - 2; n >= msgLen; n-- ) {
        if (padded[n] != padch)
            return NULL;
    }

    if ((msg = (uint8_t *)malloc(msgLen + 1)) == NULL)
        return NULL;

    memcpy(msg, padded, msgLen);

    return msg;
}


static uint8_t *__x923_pad( const uint8_t *msg, const size_t msgLen, const uint8_t padSize, size_t *newMsgLen ) {
    uint8_t *paddedMsg;
    size_t paddedLen;
    uint8_t padch;

    padch = (padSize - (msgLen % padSize));
    paddedLen = msgLen + padch;
    *newMsgLen = paddedLen;

    if ((paddedMsg = malloc(paddedLen)) == NULL)
        return NULL;
    
    memcpy(paddedMsg, msg, msgLen);
    
    for ( size_t n = msgLen; n < paddedLen - 1; n++ )
        paddedMsg[n] = 0;

    paddedMsg[paddedLen - 1] = padch;

    return paddedMsg;
}


static uint8_t *__x923_unpad( const uint8_t *padded, const size_t paddedLen, const uint8_t padSize, size_t *newMsgLen ) {
    uint8_t *msg;
    size_t msgLen;
    uint8_t padch;

    padch = padded[paddedLen - 1];

    if (padch > padSize)
        return NULL;

    msgLen = paddedLen - (size_t)padch;
    *newMsgLen = msgLen;

    for ( size_t n = paddedLen - 2; n >= msgLen; n-- ) {
        if (padded[n] != 0) {
            return NULL;
        }
    }

    if ((msg = (uint8_t *)malloc(msgLen + 1)) == NULL)
        return NULL;

    memcpy(msg, padded, msgLen);

    return msg;
}


uint8_t *Padder(enum _xcrypto_padding_types padding, uint8_t *msg, size_t msgLen, uint8_t padSize, size_t *newMsgLen) {
    switch (padding) {
        case PKCS7:
            return __pkcs7_pad(msg, msgLen, padSize, newMsgLen);
        
        case X923:
            return __x923_pad(msg, msgLen, padSize, newMsgLen);
        
        default:
            return NULL;
            break;
    }
}


uint8_t *Unpadder(enum _xcrypto_padding_types padding, uint8_t *padded, size_t paddedLen, uint8_t padSize, size_t *newMsgLen) {
    switch (padding)
    {
    case PKCS7:
        return __pkcs7_unpad(padded, paddedLen, padSize, newMsgLen);
    
    case X923:
        return __x923_unpad(padded, paddedLen, padSize, newMsgLen);
    
    default:
        return NULL;
        break;
    }
}