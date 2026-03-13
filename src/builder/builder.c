#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>
#include <bcrypt.h>
#include "aes.h"
#include "monocypher.h"

#pragma comment(lib, "bcrypt.lib")

#include "stub_data.h"

#define MARKER "CRYPTEXT_v2"
#define SALT_SIZE 16
#define IV_SIZE 16
#define MAX_MSG_SIZE 4096

typedef struct {
    uint8_t salt_real[SALT_SIZE];
    uint8_t iv_real[IV_SIZE];
    uint8_t verifier_real[32];
    uint32_t msg_len_real;

    uint8_t salt_decoy[SALT_SIZE];
    uint8_t iv_decoy[IV_SIZE];
    uint8_t verifier_decoy[32];
    uint32_t msg_len_decoy;
} CryptexHeader;

void derive_key(const char* password, const uint8_t* salt, uint8_t* key) {
    crypto_argon2_config config = { CRYPTO_ARGON2_ID, 65536, 3, 1 }; 
    crypto_argon2_inputs inputs = { (const uint8_t*)password, salt, (uint32_t)strlen(password), SALT_SIZE };
    void* work_area = malloc(1024 * config.nb_blocks);
    crypto_argon2(key, 32, work_area, config, inputs, crypto_argon2_no_extras);
    free(work_area);
}

void generate_random(uint8_t* buf, size_t size) {
    BCryptGenRandom(NULL, buf, (ULONG)size, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
}

void encrypt_payload(const char* msg, const char* pass, uint8_t* salt, uint8_t* iv, uint8_t* verifier, uint32_t* msg_len, uint8_t** out_buf, uint32_t* out_len) {
    *msg_len = (uint32_t)strlen(msg);
    generate_random(salt, SALT_SIZE);
    generate_random(iv, IV_SIZE);

    uint8_t key[32];
    derive_key(pass, salt, key);

    crypto_blake2b_ctx v_ctx;
    crypto_blake2b_init(&v_ctx, 32);
    crypto_blake2b_update(&v_ctx, key, 32);
    crypto_blake2b_final(&v_ctx, verifier);

    *out_len = ((*msg_len + 15) / 16) * 16;
    *out_buf = (uint8_t*)calloc(1, *out_len);
    memcpy(*out_buf, msg, *msg_len);

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_encrypt_buffer(&ctx, *out_buf, *out_len);
    crypto_wipe(key, 32);
}

int main() {
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);

    printf("\n");
    printf("  ██████╗██████╗ ██╗   ██╗██████╗ ████████╗███████╗██╗  ██╗████████╗\n");
    printf("  ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔════╝╚██╗██╔╝╚══██╔══╝\n");
    printf("  ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   █████╗   ╚███╔╝    ██║   \n");
    printf("  ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██╔══╝   ██╔██╗    ██║   \n");
    printf("  ╚██████╗██║  ██║   ██║   ██║        ██║   ███████╗██╔╝ ██╗   ██║   \n");
    printf("   ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   ╚══════╝╚═╝  ╚═╝   ╚═╝   \n");
    printf("           \x1b[36mgithub - @tuna4ll\x1b[0m\n\n");
    printf("  \x1b[31m\"Tis habere suntcus est leke les habere suntcus est!\"\x1b[0m\n\n");
    printf("  --- Cryptext Advanced Builder ---\n\n");
    
    char msg_real[MAX_MSG_SIZE], pass_real[256];
    char msg_decoy[MAX_MSG_SIZE], pass_decoy[256];
    char output_name[256];

    printf("[REAL] Enter secret message: ");
    fgets(msg_real, MAX_MSG_SIZE, stdin); msg_real[strcspn(msg_real, "\r\n")] = 0;
    printf("[REAL] Set password: ");
    fgets(pass_real, 256, stdin); pass_real[strcspn(pass_real, "\r\n")] = 0;

    CryptexHeader header;
    char choice[16];
    int has_decoy = 0;
    printf("\nAdd a decoy message? (y/n): ");
    fgets(choice, 16, stdin);
    if (choice[0] == 'y' || choice[0] == 'Y') has_decoy = 1;

    if (has_decoy) {
        printf("[DECOY] Enter fake message: ");
        fgets(msg_decoy, MAX_MSG_SIZE, stdin); msg_decoy[strcspn(msg_decoy, "\r\n")] = 0;
        printf("[DECOY] Set decoy password: ");
        fgets(pass_decoy, 256, stdin); pass_decoy[strcspn(pass_decoy, "\r\n")] = 0;
    } else {
        header.msg_len_decoy = 0;
        memset(header.salt_decoy, 0, SALT_SIZE);
        memset(header.iv_decoy, 0, IV_SIZE);
        memset(header.verifier_decoy, 0, 32);
    }

    printf("\nOutput filename: ");
    fgets(output_name, 256, stdin); output_name[strcspn(output_name, "\r\n")] = 0;

    char final_output[300];
    if (strstr(output_name, ".exe") == NULL) sprintf(final_output, "%s.exe", output_name);
    else strcpy(final_output, output_name);

    uint8_t *buf_real = NULL, *buf_decoy = NULL;
    uint32_t len_real = 0, len_decoy = 0;

    encrypt_payload(msg_real, pass_real, header.salt_real, header.iv_real, header.verifier_real, &header.msg_len_real, &buf_real, &len_real);
    
    if (has_decoy) {
        encrypt_payload(msg_decoy, pass_decoy, header.salt_decoy, header.iv_decoy, header.verifier_decoy, &header.msg_len_decoy, &buf_decoy, &len_decoy);
    }

    FILE* fout = fopen(final_output, "wb");
    if (!fout) { perror("Error"); return 1; }

    // Steathy De-masking write
    for (uint32_t i = 0; i < stub_data_len; i++) {
        fputc(stub_data[i] ^ stub_mask, fout);
    }
    
    fseek(fout, 0, SEEK_END);
    fwrite(MARKER, 1, strlen(MARKER), fout);
    fwrite(&header, sizeof(CryptexHeader), 1, fout);
    fwrite(buf_real, 1, len_real, fout);
    if (has_decoy) {
        fwrite(buf_decoy, 1, len_decoy, fout);
    }
    fclose(fout);

    printf("\n  \x1b[32mSuccess!\x1b[0m stand-alone '\x1b[33m%s\x1b[0m' created.\n", final_output);
    
    crypto_wipe(pass_real, 256); 
    crypto_wipe(msg_real, MAX_MSG_SIZE);
    if (has_decoy) {
        crypto_wipe(pass_decoy, 256);
        crypto_wipe(msg_decoy, MAX_MSG_SIZE);
        free(buf_decoy);
    }
    free(buf_real);
    return 0;
}
