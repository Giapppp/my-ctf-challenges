// Base85 encoding/decoding with no padding

#include "base85.h"

const uint8_t BASE85_ALPHABET[] = 
    "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstu";
    
uint8_t BASE85_INV_ALPHABET[256];

__attribute__((constructor))
static void init_b85() {
    memset(BASE85_INV_ALPHABET, 0, sizeof BASE85_INV_ALPHABET);
    for (int i = 0; i < 85; i++) {
        BASE85_INV_ALPHABET[BASE85_ALPHABET[i]] = i;
    }
}

void input_b85(uint8_t *buf, int n) {
    while (n > 0) {
        switch (n) {
            case 1: {
                // need 2
                fread(buf, 1, 2, stdin);
                uint8_t b[5];
                b[0] = BASE85_INV_ALPHABET[buf[0]];
                b[1] = BASE85_INV_ALPHABET[buf[1]];
                b[2] = 84;
                b[3] = 84;
                b[4] = 84;
                
                uint32_t chunk = b[0];
                chunk = chunk * 85 + b[1];
                chunk = chunk * 85 + b[2];
                chunk = chunk * 85 + b[3];
                chunk = chunk * 85 + b[4];

                buf[0] = (chunk >> 24) & 0xFF;
                return;
            }

            case 2: {
                // need 3
                fread(buf, 1, 3, stdin);
                uint8_t b[5];
                b[0] = BASE85_INV_ALPHABET[buf[0]];
                b[1] = BASE85_INV_ALPHABET[buf[1]];
                b[2] = BASE85_INV_ALPHABET[buf[2]];
                b[3] = 84; // pad with 'u'
                b[4] = 84;
                
                uint32_t chunk = b[0];
                chunk = chunk * 85 + b[1];
                chunk = chunk * 85 + b[2];
                chunk = chunk * 85 + b[3];
                chunk = chunk * 85 + b[4];

                buf[0] = (chunk >> 24) & 0xFF;
                buf[1] = (chunk >> 16) & 0xFF;
                return;
            }

            case 3: {
                // need 4
                fread(buf, 1, 4, stdin);
                uint8_t b[5];
                b[0] = BASE85_INV_ALPHABET[buf[0]];
                b[1] = BASE85_INV_ALPHABET[buf[1]];
                b[2] = BASE85_INV_ALPHABET[buf[2]];
                b[3] = BASE85_INV_ALPHABET[buf[3]];
                b[4] = 84; // pad with 'u'
                
                uint32_t chunk = b[0];
                chunk = chunk * 85 + b[1];
                chunk = chunk * 85 + b[2];
                chunk = chunk * 85 + b[3];
                chunk = chunk * 85 + b[4];

                buf[0] = (chunk >> 24) & 0xFF;
                buf[1] = (chunk >> 16) & 0xFF;
                buf[2] = (chunk >> 8) & 0xFF;
                return;
            }

            default: {
                // need 5
                fread(buf, 1, 5, stdin);
                uint8_t b[5];
                b[0] = BASE85_INV_ALPHABET[buf[0]];
                b[1] = BASE85_INV_ALPHABET[buf[1]];
                b[2] = BASE85_INV_ALPHABET[buf[2]];
                b[3] = BASE85_INV_ALPHABET[buf[3]];
                b[4] = BASE85_INV_ALPHABET[buf[4]];

                uint32_t chunk = b[0];
                chunk = chunk * 85 + b[1];
                chunk = chunk * 85 + b[2];
                chunk = chunk * 85 + b[3];
                chunk = chunk * 85 + b[4];

                buf[0] = (chunk >> 24) & 0xFF;
                buf[1] = (chunk >> 16) & 0xFF;
                buf[2] = (chunk >> 8)  & 0xFF;
                buf[3] = (chunk >> 0)  & 0xFF;
                
                buf += 4;
                n -= 4;
                break; 
            }
        }
    }
}


void print_b85(const uint8_t *buf, int n) {
    // Process main bulk in 4-byte chunks
    while (n >= 4) {
        uint32_t chunk = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
        uint8_t c[5];
        
        c[4] = chunk % 85; chunk /= 85;
        c[3] = chunk % 85; chunk /= 85;
        c[2] = chunk % 85; chunk /= 85;
        c[1] = chunk % 85; chunk /= 85;
        c[0] = chunk;
        
        // print 5
        fputc(BASE85_ALPHABET[c[0]], stdout);
        fputc(BASE85_ALPHABET[c[1]], stdout);
        fputc(BASE85_ALPHABET[c[2]], stdout);
        fputc(BASE85_ALPHABET[c[3]], stdout);
        fputc(BASE85_ALPHABET[c[4]], stdout);
        
        buf += 4;
        n -= 4;
    }

    // Handle remaining bytes
    if (n > 0) {
        uint32_t chunk = 0;
        uint8_t c[5];

        if (n == 3) {
            chunk = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8);
        } else if (n == 2) {
            chunk = (buf[0] << 24) | (buf[1] << 16);
        } else if (n == 1) {
            chunk = (buf[0] << 24);
        }

        c[4] = chunk % 85; chunk /= 85;
        c[3] = chunk % 85; chunk /= 85;
        c[2] = chunk % 85; chunk /= 85;
        c[1] = chunk % 85; chunk /= 85;
        c[0] = chunk;

        // print N+1
        for (int i = 0; i < (n + 1); i++) {
            fputc(BASE85_ALPHABET[c[i]], stdout);
        }
    }
}