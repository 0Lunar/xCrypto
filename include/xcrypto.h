#ifndef __xcrypto_header__
#define __xcrypto_header__

#include <stdint.h>
#include <stdbool.h>
#include "aes.h"
#include "des.h"


#define IS_LITTLE_ENDIAN() ((*(uint8_t*)&(uint16_t){1}) == 1)  


enum _cipher_modes {
    ECB
};

enum _ciphers {
    AES
};


typedef enum _cipher_modes CipherModes;
typedef enum _ciphers Ciphers;

#endif