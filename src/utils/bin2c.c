#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc < 3) return 1;
    FILE *in = fopen(argv[1], "rb");
    if (!in) return 1;
    FILE *out = fopen(argv[2], "w");
    if (!out) { fclose(in); return 1; }

    fprintf(out, "const unsigned char stub_data[] = {\n");
    unsigned char buf[16];
    size_t n, total = 0;
    const unsigned char mask = 0xAA; 
    while ((n = fread(buf, 1, 16, in)) > 0) {
        fprintf(out, "  ");
        for (size_t i = 0; i < n; i++) {
            fprintf(out, "0x%02X, ", buf[i] ^ mask);
            total++;
        }
        fprintf(out, "\n");
    }
    fprintf(out, "};\nconst unsigned int stub_data_len = %u;\n", (unsigned int)total);
    fprintf(out, "const unsigned char stub_mask = 0x%02X;\n", mask);
    fclose(in);
    fclose(out);
    return 0;
}
