#ifndef __xcrypto_header__
#define __xcrypto_header__

#include <stdint.h>
#include <stdbool.h>
#include "aes.h"
#include "des.h"
#include "rsa.h"
#include "rng.h"
#include "pad.h"


enum _cipher_modes {
    ECB
};

enum _ciphers {
    AES,
    DES
};


typedef enum _cipher_modes CipherModes;
typedef enum _ciphers Ciphers;

#endif