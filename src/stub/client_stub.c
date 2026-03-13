#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "aes.h"
#include "monocypher.h"

#define MARKER "CRYPTEXT_v2"
#define SALT_SIZE 16
#define IV_SIZE 16

typedef struct {
    uint8_t salt_real[SALT_SIZE];
    uint8_t iv_real[IV_SIZE];
    uint8_t verifier_real[32];
    uint32_t msg_len_real;

    uint8_t salt_decoy[SALT_SIZE];
    uint8_t iv_decoy[16];
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

void defensive_check() {
    // Anti-Debug
    if (IsDebuggerPresent()) exit(1);

    // Anti-VM (Common artifacts)
    const char* vm_files[] = {
        "C:\\windows\\System32\\Drivers\\VBoxGuest.sys",
        "C:\\windows\\System32\\Drivers\\vmtoolsd.exe"
    };
    for (int i = 0; i < 2; i++) {
        FILE *f = fopen(vm_files[i], "r");
        if (f) { fclose(f); exit(1); }
    }
}

int main(int argc, char* argv[]) {
    defensive_check();
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);

    FILE* f = fopen(argv[0], "rb");
    if (!f) return 1;

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    int marker_len = strlen(MARKER);
    int found = 0;
    long marker_pos = 0;

    for (long i = file_size - marker_len; i >= 0; i--) {
        fseek(f, i, SEEK_SET);
        char buf[16] = {0};
        fread(buf, 1, marker_len, f);
        if (memcmp(buf, MARKER, marker_len) == 0) {
            found = 1;
            marker_pos = i;
            break;
        }
    }

    if (!found) {
        fclose(f);
        return 1;
    }

    CryptexHeader header;
    fseek(f, marker_pos + marker_len, SEEK_SET);
    fread(&header, sizeof(CryptexHeader), 1, f);

    char password[256];
    printf("\n");
    printf("  ██████╗██████╗ ██╗   ██╗██████╗ ████████╗███████╗██╗  ██╗████████╗\n");
    printf("  ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔════╝╚██╗██╔╝╚══██╔══╝\n");
    printf("  ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   █████╗   ╚███╔╝    ██║   \n");
    printf("  ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██╔══╝   ██╔██╗    ██║   \n");
    printf("  ╚██████╗██║  ██║   ██║   ██║        ██║   ███████╗██╔╝ ██╗   ██║   \n");
    printf("   ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   ╚══════╝╚═╝  ╚═╝   ╚═╝   \n");
    printf("           \x1b[36mgithub - @tuna4ll\x1b[0m\n\n");
    printf("  \x1b[31m\"Tis habere suntcus est leke les habere suntcus est!\"\x1b[0m\n\n");
    printf("  --- Cryptext Security Gateway ---\n");
    printf("  Authorization required: ");
    if (fgets(password, 256, stdin) == NULL) return 1;
    password[strcspn(password, "\r\n")] = 0;

    uint8_t key[32];
    uint8_t current_verifier[32];
    uint32_t active_msg_len = 0;
    uint32_t active_padded_len = 0;
    uint8_t* active_iv = NULL;
    long payload_offset = 0;

    // Check Real Password
    derive_key(password, header.salt_real, key);
    crypto_blake2b_ctx v_ctx;
    crypto_blake2b_init(&v_ctx, 32);
    crypto_blake2b_update(&v_ctx, key, 32);
    crypto_blake2b_final(&v_ctx, current_verifier);

    if (memcmp(current_verifier, header.verifier_real, 32) == 0) {
        active_msg_len = header.msg_len_real;
        active_iv = header.iv_real;
        payload_offset = marker_pos + marker_len + sizeof(CryptexHeader);
    } else if (header.msg_len_decoy > 0) {
        // Try Decoy Password only if it exists
        derive_key(password, header.salt_decoy, key);
        crypto_blake2b_init(&v_ctx, 32);
        crypto_blake2b_update(&v_ctx, key, 32);
        crypto_blake2b_final(&v_ctx, current_verifier);

        if (memcmp(current_verifier, header.verifier_decoy, 32) == 0) {
            active_msg_len = header.msg_len_decoy;
            active_iv = header.iv_decoy;
            uint32_t padded_real = ((header.msg_len_real + 15) / 16) * 16;
            payload_offset = marker_pos + marker_len + sizeof(CryptexHeader) + padded_real;
        }
    }

    if (payload_offset == 0) {
        // Self-destruct logic (unchanged but standard fail)
        char cmd[512];
        sprintf(cmd, "cmd.exe /c timeout /t 1 /nobreak > NUL && del \"%s\"", argv[0]);
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
        return 1;
    }

    active_padded_len = ((active_msg_len + 15) / 16) * 16;
    uint8_t* encrypted_buf = (uint8_t*)malloc(active_padded_len);
    fseek(f, payload_offset, SEEK_SET);
    fread(encrypted_buf, 1, active_padded_len, f);
    fclose(f);

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, active_iv);
    AES_CBC_decrypt_buffer(&ctx, encrypted_buf, active_padded_len);

    printf("\n  \x1b[32mDecrypted Content:\x1b[0m ");
    for (uint32_t i = 0; i < active_msg_len; i++) putchar(encrypted_buf[i]);
    printf("\n\n  Press Enter to securely clear and exit...");
    while (getchar() != '\n' && getchar() != EOF); 
    getchar();

    system("cls"); // Anti-forensics: Clear screen

    crypto_wipe(password, sizeof(password));
    crypto_wipe(key, sizeof(key));
    crypto_wipe(encrypted_buf, active_padded_len);
    free(encrypted_buf);
    return 0;
}
