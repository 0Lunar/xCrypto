#define _POSIX_C_SOURCE 200809L

#include <xcrypto.h>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


#define TEST_SIZE_MB 256ULL
#define TEST_SIZE (TEST_SIZE_MB * 1024ULL * 1024ULL)
#define ITERATIONS 5


static inline uint64_t get_ns() {
    struct timespec t;

    clock_gettime(CLOCK_MONOTONIC_RAW, &t);

    return ((uint64_t)t.tv_sec * 1000000000ULL) + t.tv_nsec;
}


void printhex(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++)
        printf("%02x", buf[i]);

    puts("");
}


const char *algo_name(HashAlgorithm alg) {
    switch (alg) {
        case XCRYPTO_MD5:    return "MD5";
        case XCRYPTO_SHA0:   return "SHA0";
        case XCRYPTO_SHA1:   return "SHA1";
        case XCRYPTO_SHA224: return "SHA224";
        case XCRYPTO_SHA256: return "SHA256";
        case XCRYPTO_SHA512: return "SHA512";
        default:             return "UNKNOWN";
    }
}


void benchmark(HashAlgorithm alg, const uint8_t *buf, size_t size) {
    HashCtx *ctx;
    uint8_t digest[64];

    double best_ms = 1e30;
    double worst_ms = 0.0;
    double total_ms = 0.0;

    printf("=== %s ===\n", algo_name(alg));

    for (int i = 0; i < ITERATIONS; i++) {
        uint64_t start;
        uint64_t end;
        double elapsed_ms;
        double throughput;

        ctx = NewHash();

        if (!ctx) {
            puts("NewHash failed");
            exit(1);
        }

        if (HashSetAlgorithm(ctx, alg) != HASH_SUCCESS) {
            puts("HashSetAlgorithm failed");
            exit(1);
        }

        start = get_ns();

        HashUpdate(ctx, buf, size);
        HashFinalize(ctx, digest, HashDigestSize[alg]);

        end = get_ns();

        elapsed_ms = (double)(end - start) / 1000000.0;

        throughput =
            ((double)size / (1024.0 * 1024.0)) /
            (elapsed_ms / 1000.0);

        if (elapsed_ms < best_ms)
            best_ms = elapsed_ms;

        if (elapsed_ms > worst_ms)
            worst_ms = elapsed_ms;

        total_ms += elapsed_ms;

        printf(
            "Run %d: %9.3f ms | %9.2f MiB/s\n",
            i + 1,
            elapsed_ms,
            throughput
        );

        HashFree(ctx);
    }

    double avg_ms = total_ms / ITERATIONS;

    double avg_throughput =
        ((double)size / (1024.0 * 1024.0)) /
        (avg_ms / 1000.0);

    printf("\nDigest: ");
    printhex(digest, HashDigestSize[alg]);

    printf("\n");
    printf("Data Size : %llu MiB\n", TEST_SIZE_MB);
    printf("Best Time : %.3f ms\n", best_ms);
    printf("Worst Time: %.3f ms\n", worst_ms);
    printf("Avg Time  : %.3f ms\n", avg_ms);
    printf("Avg Speed : %.2f MiB/s\n", avg_throughput);

    puts("\n----------------------------------------\n");
}


int main(void) {
    uint8_t *buf;

    if (posix_memalign((void**)&buf, 64, TEST_SIZE) != 0) {
        puts("Allocation failed");
        return 1;
    }

    for (size_t i = 0; i < TEST_SIZE; i++)
        buf[i] = (uint8_t)((i * 1315423911u) ^ (i >> 3));

    benchmark(XCRYPTO_MD5,    buf, TEST_SIZE);
    benchmark(XCRYPTO_SHA1,   buf, TEST_SIZE);
    benchmark(XCRYPTO_SHA224, buf, TEST_SIZE);
    benchmark(XCRYPTO_SHA256, buf, TEST_SIZE);
    benchmark(XCRYPTO_SHA512, buf, TEST_SIZE);

    free(buf);

    return 0;
}