#include "rng.h"


static void csprng_buf( void *buf, size_t len ) {
#if defined(_WIN32)
    #include <bcrypt.h>
    BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
#else
    FILE *f = fopen("/dev/urandom", "rb");
    fread(buf, 1, len, f);
    fclose(f);
#endif
}


void gen_prime( mpz_t prime, int bits ) {
    gmp_randstate_t state;
    mpz_t seed;

    gmp_randinit_mt(state);
    mpz_init(seed);

    uint8_t buf[32];
    csprng_buf(buf, sizeof(buf));
    mpz_import(seed, sizeof(buf), 1, 1, 0, 0, buf);
    gmp_randseed(state, seed);

    mpz_t candidate;
    mpz_init(candidate);

    do {
        mpz_urandomb(candidate, state, bits);
        mpz_setbit(candidate, bits - 1);  /* forza il bit più alto: garantisce `bits` bit */
        mpz_setbit(candidate, 0);         /* forza dispari */
        mpz_nextprime(prime, candidate);
    } while (mpz_sizeinbase(prime, 2) != (size_t)bits);  /* assicura esattamente `bits` bit */

    mpz_clear(candidate);
    mpz_clear(seed);
    gmp_randclear(state);
}