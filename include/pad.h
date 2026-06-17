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


typedef enum _xcrypto_padding_types PadTypes;


uint8_t *Padder(PadTypes padding, uint8_t *msg, size_t msgLen, uint8_t padSize, size_t *newMsgLen);
uint8_t *Unpadder(PadTypes padding, uint8_t *padded, size_t paddedLen, uint8_t padSize, size_t *newMsgLen);


#endif