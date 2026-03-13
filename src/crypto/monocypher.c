#include "monocypher.h"
#include <string.h>

typedef int8_t   i8;
typedef uint8_t  u8;
typedef uint32_t u32;
typedef int32_t  i32;
typedef int64_t  i64;
typedef uint64_t u64;

static u32 load32_le(const u8 s[4]) {
    return ((u32)s[0] << 0) | ((u32)s[1] << 8) | ((u32)s[2] << 16) | ((u32)s[3] << 24);
}
static u64 load64_le(const u8 s[8]) {
    return (u64)load32_le(s) | ((u64)load32_le(s + 4) << 32);
}
static void store32_le(u8 out[4], u32 in) {
    out[0] = (u8)(in & 0xff); out[1] = (u8)((in >> 8) & 0xff);
    out[2] = (u8)((in >> 16) & 0xff); out[3] = (u8)((in >> 24) & 0xff);
}
static void store64_le(u8 out[8], u64 in) {
    store32_le(out, (u32)in); store32_le(out + 4, (u32)(in >> 32));
}
static void load64_le_buf(u64 *dst, const u8 *src, size_t size) {
    for(size_t i=0; i<size; i++) { dst[i] = load64_le(src + i * 8); }
}
static void store64_le_buf(u8 *dst, const u64 *src, size_t size) {
    for(size_t i=0; i<size; i++) { store64_le(dst + i * 8, src[i]); }
}
static u64 rotr64(u64 x, u64 n) { return (x >> n) ^ (x << (64 - n)); }

void crypto_wipe(void *secret, size_t size) {
    volatile u8 *v_secret = (u8*)secret;
    for(size_t i=0; i<size; i++) { v_secret[i] = 0; }
}

static const u64 blake2b_iv[8] = {
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
};
static const u8 blake2b_sigma[12][16] = {
	{  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
	{ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
	{  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
	{  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
	{  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
	{ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
	{ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
	{  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
	{ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
};

#define G(a, b, c, d, x, y) \
	a += b + x;  d = rotr64(d ^ a, 32); \
	c += d;      b = rotr64(b ^ c, 24); \
	a += b + y;  d = rotr64(d ^ a, 16); \
	c += d;      b = rotr64(b ^ c, 63)

#define ROUND(i) \
	G(v0, v4, v8,  v12, m[blake2b_sigma[i][ 0]], m[blake2b_sigma[i][ 1]]); \
	G(v1, v5, v9,  v13, m[blake2b_sigma[i][ 2]], m[blake2b_sigma[i][ 3]]); \
	G(v2, v6, v10, v14, m[blake2b_sigma[i][ 4]], m[blake2b_sigma[i][ 5]]); \
	G(v3, v7, v11, v15, m[blake2b_sigma[i][ 6]], m[blake2b_sigma[i][ 7]]); \
	G(v0, v5, v10, v15, m[blake2b_sigma[i][ 8]], m[blake2b_sigma[i][ 9]]); \
	G(v1, v6, v11, v12, m[blake2b_sigma[i][10]], m[blake2b_sigma[i][11]]); \
	G(v2, v7, v8,  v13, m[blake2b_sigma[i][12]], m[blake2b_sigma[i][13]]); \
	G(v3, v4, v9,  v14, m[blake2b_sigma[i][14]], m[blake2b_sigma[i][15]])

static void blake2b_compress(crypto_blake2b_ctx *ctx, int is_last_block) {
    u64* m = ctx->input;
    u64 v0 = ctx->hash[0]; u64 v8 = blake2b_iv[0];
    u64 v1 = ctx->hash[1]; u64 v9 = blake2b_iv[1];
    u64 v2 = ctx->hash[2]; u64 v10 = blake2b_iv[2];
    u64 v3 = ctx->hash[3]; u64 v11 = blake2b_iv[3];
    u64 v4 = ctx->hash[4]; u64 v12 = blake2b_iv[4] ^ ctx->input_offset[0];
    u64 v5 = ctx->hash[5]; u64 v13 = blake2b_iv[5] ^ ctx->input_offset[1];
    u64 v6 = ctx->hash[6]; u64 v14 = blake2b_iv[6] ^ (is_last_block ? ~0ULL : 0ULL);
    u64 v7 = ctx->hash[7]; u64 v15 = blake2b_iv[7];

    ROUND(0); ROUND(1); ROUND(2); ROUND(3); ROUND(4); ROUND(5);
    ROUND(6); ROUND(7); ROUND(8); ROUND(9); ROUND(10); ROUND(11);

    ctx->hash[0] ^= v0 ^ v8; ctx->hash[1] ^= v1 ^ v9;
    ctx->hash[2] ^= v2 ^ v10; ctx->hash[3] ^= v3 ^ v11;
    ctx->hash[4] ^= v4 ^ v12; ctx->hash[5] ^= v5 ^ v13;
    ctx->hash[6] ^= v6 ^ v14; ctx->hash[7] ^= v7 ^ v15;
}

void crypto_blake2b_init(crypto_blake2b_ctx *ctx, size_t hash_size) {
    memcpy(ctx->hash, blake2b_iv, 64);
    ctx->hash[0] ^= 0x01010000 ^ (u64)hash_size;
    ctx->input_offset[0] = 0; ctx->input_offset[1] = 0;
    ctx->input_idx = 0; ctx->hash_size = hash_size;
    memset(ctx->input, 0, 128);
}

void crypto_blake2b_update(crypto_blake2b_ctx *ctx, const uint8_t *message, size_t message_size) {
    while (message_size > 0) {
        if (ctx->input_idx == 128) {
            blake2b_compress(ctx, 0);
            ctx->input_idx = 0;
            memset(ctx->input, 0, 128);
        }
        size_t n = 128 - ctx->input_idx;
        if (n > message_size) n = message_size;
        for (size_t i = 0; i < n; i++) {
            ctx->input[(ctx->input_idx + i) >> 3] |= (u64)message[i] << (8 * ((ctx->input_idx + i) & 7));
        }
        ctx->input_idx += n;
        ctx->input_offset[0] += n;
        if (ctx->input_offset[0] < n) ctx->input_offset[1]++;
        message += n;
        message_size -= n;
    }
}

void crypto_blake2b_final(crypto_blake2b_ctx *ctx, uint8_t *hash) {
    blake2b_compress(ctx, 1);
    for (size_t i = 0; i < ctx->hash_size; i++) {
        hash[i] = (u8)((ctx->hash[i >> 3] >> (8 * (i & 7))) & 0xff);
    }
    crypto_wipe(ctx, sizeof(*ctx));
}

// Argon2
typedef struct { u64 a[128]; } blk;
static void blake_update_32(crypto_blake2b_ctx *ctx, u32 input) {
    u8 buf[4]; store32_le(buf, input); crypto_blake2b_update(ctx, buf, 4);
}
static void blake_update_32_buf(crypto_blake2b_ctx *ctx, const u8 *buf, u32 size) {
    blake_update_32(ctx, size); if (size > 0) crypto_blake2b_update(ctx, buf, size);
}
static void extended_hash(u8 *digest, u32 digest_size, const u8 *input, u32 input_size) {
    crypto_blake2b_ctx ctx; crypto_blake2b_init(&ctx, digest_size < 64 ? digest_size : 64);
    blake_update_32(&ctx, digest_size); crypto_blake2b_update(&ctx, input, input_size);
    crypto_blake2b_final(&ctx, digest);
    if (digest_size > 64) {
        u32 r = (digest_size + 31) / 32 - 2;
        for (u32 i = 0; i < r; i++) {
            u8 tmp[64]; memcpy(tmp, digest + i * 32, 64);
            crypto_blake2b_ctx ext; crypto_blake2b_init(&ext, 64);
            crypto_blake2b_update(&ext, tmp, 64); crypto_blake2b_final(&ext, digest + (i + 1) * 32);
        }
        u32 last_size = digest_size - (r + 1) * 32;
        u8 tmp[64]; memcpy(tmp, digest + r * 32, 64);
        crypto_blake2b_ctx ext; crypto_blake2b_init(&ext, last_size);
        crypto_blake2b_update(&ext, tmp, 64); crypto_blake2b_final(&ext, digest + (r + 1) * 32);
    }
}

#define ARGON2_G(a, b, c, d) \
    a += b + (2ULL * (u32)a * (u32)b); d = rotr64(d ^ a, 32); \
    c += d + (2ULL * (u32)c * (u32)d); b = rotr64(b ^ c, 24); \
    a += b + (2ULL * (u32)a * (u32)b); d = rotr64(d ^ a, 16); \
    c += d + (2ULL * (u32)c * (u32)d); b = rotr64(b ^ c, 63)

static void g_rounds(blk *b) {
    #define R(v0,v1,v2,v3,v4,v5,v6,v7,v8,v9,v10,v11,v12,v13,v14,v15) \
        ARGON2_G(v0,v4,v8,v12); ARGON2_G(v1,v5,v9,v13); ARGON2_G(v2,v6,v10,v14); ARGON2_G(v3,v7,v11,v15); \
        ARGON2_G(v0,v5,v10,v15); ARGON2_G(v1,v6,v11,v12); ARGON2_G(v2,v7,v8,v13); ARGON2_G(v3,v4,v9,v14)
    for (int i = 0; i < 128; i += 16) { R(b->a[i+0],b->a[i+1],b->a[i+2],b->a[i+3],b->a[i+4],b->a[i+5],b->a[i+6],b->a[i+7],b->a[i+8],b->a[i+9],b->a[i+10],b->a[i+11],b->a[i+12],b->a[i+13],b->a[i+14],b->a[i+15]); }
    for (int i = 0; i <  16; i +=  2) { R(b->a[i+0],b->a[i+1],b->a[i+16],b->a[i+17],b->a[i+32],b->a[i+33],b->a[i+48],b->a[i+49],b->a[i+64],b->a[i+65],b->a[i+80],b->a[i+81],b->a[i+96],b->a[i+97],b->a[i+112],b->a[i+113]); }
    #undef R
}

const crypto_argon2_extras crypto_argon2_no_extras = {0,0,0,0};

void crypto_argon2(u8 *hash, u32 hash_size, void *work_area, crypto_argon2_config config, crypto_argon2_inputs inputs, crypto_argon2_extras extras) {
    u32 segment_size = config.nb_blocks / config.nb_lanes / 4;
    u32 lane_size = segment_size * 4;
    u32 nb_blocks_total = lane_size * config.nb_lanes;
    blk *blocks = (blk*)work_area;
    u8 h0[72]; crypto_blake2b_ctx ctx; crypto_blake2b_init(&ctx, 64);
    blake_update_32(&ctx, config.nb_lanes); blake_update_32(&ctx, hash_size); blake_update_32(&ctx, config.nb_blocks);
    blake_update_32(&ctx, config.nb_passes); blake_update_32(&ctx, 0x13); blake_update_32(&ctx, config.algorithm);
    blake_update_32_buf(&ctx, inputs.pass, inputs.pass_size); blake_update_32_buf(&ctx, inputs.salt, inputs.salt_size);
    blake_update_32_buf(&ctx, extras.key, extras.key_size); blake_update_32_buf(&ctx, extras.ad, extras.ad_size);
    crypto_blake2b_final(&ctx, h0);

    u8 hash_area[1024];
    for (u32 l = 0; l < config.nb_lanes; l++) {
        for (u32 i = 0; i < 2; i++) {
            store32_le(h0 + 64, i); store32_le(h0 + 68, l);
            extended_hash(hash_area, 1024, h0, 72);
            load64_le_buf(blocks[l * lane_size + i].a, hash_area, 128);
        }
    }

    blk tmp; int constant_time = config.algorithm != CRYPTO_ARGON2_D;
    for (u32 pass = 0; pass < config.nb_passes; pass++) {
        for (u32 slice = 0; slice < 4; slice++) {
            if (slice == 2 && config.algorithm == CRYPTO_ARGON2_ID) constant_time = 0;
            u32 slice_offset = slice * segment_size;
            for (u32 segment = 0; segment < config.nb_lanes; segment++) {
                blk index_block; u32 index_ctr = 1;
                u32 pass_offset = (pass == 0 && slice == 0) ? 2 : 0;
                for (u32 block = pass_offset; block < segment_size; block++) {
                    blk *current = blocks + segment * lane_size + slice_offset + block;
                    blk *prev = (slice_offset + block == 0) ? (blocks + segment * lane_size + lane_size - 1) : (current - 1);
                    u64 seed;
                    if (constant_time) {
                        if (block == pass_offset || (block % 128) == 0) {
                            memset(index_block.a, 0, 1024);
                            index_block.a[0] = pass; index_block.a[1] = segment; index_block.a[2] = slice;
                            index_block.a[3] = nb_blocks_total; index_block.a[4] = config.nb_passes; index_block.a[5] = config.algorithm;
                            index_block.a[6] = index_ctr++;
                            blk t2; memcpy(t2.a, index_block.a, 1024); g_rounds(&index_block); for(int j=0;j<128;j++) index_block.a[j] ^= t2.a[j];
                            memcpy(t2.a, index_block.a, 1024); g_rounds(&index_block); for(int j=0;j<128;j++) index_block.a[j] ^= t2.a[j];
                        }
                        seed = index_block.a[block % 128];
                    } else { seed = prev->a[0]; }
                    u32 w_start = (pass == 0) ? 0 : ((slice + 1) % 4) * segment_size;
                    u32 nb_segs = (pass == 0) ? slice : 3;
                    u32 p_lane = (pass == 0 && slice == 0) ? segment : (u32)((seed >> 32) % config.nb_lanes);
                    u32 w_size = nb_segs * segment_size + (p_lane == segment ? block - 1 : (block == 0 ? (u32)-1 : 0));
                    u64 j1 = seed & 0xffffffff; u64 x = (j1 * j1) >> 32; u64 y = (w_size * x) >> 32; u64 z = (w_size - 1) - y;
                    blk *ref = blocks + p_lane * lane_size + (w_start + (u32)z) % lane_size;
                    memcpy(tmp.a, prev->a, 1024); for (int j = 0; j < 128; j++) tmp.a[j] ^= ref->a[j];
                    if (pass == 0) memcpy(current->a, tmp.a, 1024); else for (int j = 0; j < 128; j++) current->a[j] ^= tmp.a[j];
                    g_rounds(&tmp); for (int j = 0; j < 128; j++) current->a[j] ^= tmp.a[j];
                }
            }
        }
    }
    blk *lb = blocks + lane_size - 1;
    for (u32 l = 1; l < config.nb_lanes; l++) {
        blk *nb = lb + lane_size; for (int j = 0; j < 128; j++) nb->a[j] ^= lb->a[j];
        lb = nb;
    }
    store64_le_buf(hash_area, lb->a, 128);
    extended_hash(hash, hash_size, hash_area, 1024);
    crypto_wipe(&tmp, sizeof(tmp));
}
