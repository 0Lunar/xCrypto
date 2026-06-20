#ifndef XCRYPTO_PAD_HEADER_H
#define XCRYPTO_PAD_HEADER_H


#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


enum _xcrypto_padding_types {
    PKCS7,
    X923
};


enum _xcrypto_padding_errors {
    PAD_SUCCESS,
    PAD_ERR_NULL_PTR,
    PAD_ERR_UNSUPPORTED_ALGO,
    PAD_ERR_INVALID_SIZE,
    PAD_ERR_INVALID_SEQ
};


typedef enum _xcrypto_padding_types PadTypes;
typedef enum _xcrypto_padding_errors PadError;


PadError Padder(enum _xcrypto_padding_types padding, const uint8_t *msg, size_t msgLen, uint8_t *padBuf, uint8_t padSize, size_t *newMsgLen);
PadError Unpadder(enum _xcrypto_padding_types padding, uint8_t *padded, size_t paddedLen, uint8_t *unpadBuf, uint8_t padSize, size_t *newMsgLen);


#endif