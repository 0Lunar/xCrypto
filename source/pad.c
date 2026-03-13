#include "pad.h"


uint8_t *pkcs7_pad( const uint8_t *msg, const size_t msgLen, const size_t padSize ) {
    uint8_t *paddedMsg;
    size_t paddedLen;
    uint8_t padch;

    padch = (padSize - (msgLen % padSize));
    paddedLen = msgLen + padch;

    if ( (paddedMsg = malloc(paddedLen)) == NULL )
        return NULL;
    
    memcpy(paddedMsg, msg, msgLen);

    for (size_t n = msgLen; n < paddedLen; n++)
        paddedMsg[n] = padch;

    return paddedMsg;
}


uint8_t *pkcs7_unpad( const uint8_t *padded, const size_t paddedLen ) {
    uint8_t *msg;
    size_t msgLen;
    uint8_t padch;

    padch = padded[paddedLen - 1];
    msgLen = paddedLen - (size_t)padch;

    for ( size_t n = paddedLen - 2; n >= msgLen; n-- ) {
        if (padded[n] != padch) {
            return NULL;
        }
    }

    if ((msg = (uint8_t *)malloc(msgLen)) == NULL)
        return NULL;

    memcpy(msg, padded, msgLen);
}


uint8_t *x923_pad( const uint8_t *msg, const size_t msgLen, const size_t padSize ) {
    uint8_t *paddedMsg;
    size_t paddedLen;
    uint8_t padch;

    padch = (padSize - (msgLen % padSize));
    paddedLen = msgLen + padch;

    if ((paddedMsg = malloc(paddedLen)) == NULL)
        return NULL;
    
    memcpy(paddedMsg, msg, msgLen);
    
    for ( size_t n = msgLen; n < paddedLen - 1; n++ )
        paddedMsg[n] = 0;

    paddedMsg[paddedLen - 1] = padch;

    return paddedMsg;
}


uint8_t *x923_unpad( const uint8_t *padded, const size_t paddedLen ) {
    uint8_t *msg;
    size_t msgLen;
    uint8_t padch;

    padch = padded[paddedLen - 1];
    msgLen = paddedLen - (size_t)padch;

    for ( size_t n = paddedLen - 2; n >= msgLen; n-- ) {
        if (padded[n] != 0) {
            return NULL;
        }
    }

    if ((msg = (uint8_t *)malloc(msgLen)) == NULL)
        return NULL;

    memcpy(msg, padded, msgLen);
}