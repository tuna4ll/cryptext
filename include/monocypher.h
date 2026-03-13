#ifndef MONOCYPHER_H
#define MONOCYPHER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void crypto_wipe(void *secret, size_t size);

#define CRYPTO_ARGON2_D  0
#define CRYPTO_ARGON2_I  1
#define CRYPTO_ARGON2_ID 2

typedef struct {
    uint32_t algorithm;
    uint32_t nb_blocks;
    uint32_t nb_passes;
    uint32_t nb_lanes;
} crypto_argon2_config;

typedef struct {
    const uint8_t *pass;
    const uint8_t *salt;
    uint32_t pass_size;
    uint32_t salt_size;
} crypto_argon2_inputs;

typedef struct {
    const uint8_t *key;
    const uint8_t *ad;
    uint32_t key_size;
    uint32_t ad_size;
} crypto_argon2_extras;

extern const crypto_argon2_extras crypto_argon2_no_extras;

void crypto_argon2(uint8_t *hash, uint32_t hash_size, void *work_area,
                   crypto_argon2_config config,
                   crypto_argon2_inputs inputs,
                   crypto_argon2_extras extras);

typedef struct {
    uint64_t hash[8];
    uint64_t input_offset[2];
    uint64_t input[16];
    size_t   input_idx;
    size_t   hash_size;
} crypto_blake2b_ctx;

void crypto_blake2b_init(crypto_blake2b_ctx *ctx, size_t hash_size);
void crypto_blake2b_update(crypto_blake2b_ctx *ctx, const uint8_t *message, size_t message_size);
void crypto_blake2b_final(crypto_blake2b_ctx *ctx, uint8_t *hash);

#ifdef __cplusplus
}
#endif

#endif
