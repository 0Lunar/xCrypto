#ifndef __xcrypto_header__
#define __xcrypto_header__

#include <stdint.h>
#include <stdbool.h>
#include "aes.h"
#include "des.h"


enum _cipher_modes {
    ECB
};

enum _ciphers {
    AES
};


typedef enum _cipher_modes CipherModes;
typedef enum _ciphers Ciphers;

#endif