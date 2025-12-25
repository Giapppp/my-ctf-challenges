#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

// --- Original Constants ---

const uint8_t BASE85_ALPHABET[] = 
    "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstu";

// --- Helpers ---

// Helper to convert a single hex char to integer value
int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Helper to convert hex string to binary buffer
// Returns 0 on success, -1 on error
int hex_to_bytes(const char *hex, uint8_t *buf, size_t *out_len) {
    size_t len = strlen(hex);
    if (len % 2 != 0) return -1; // Hex string must be even length

    *out_len = len / 2;
    for (size_t i = 0; i < *out_len; i++) {
        int hi = hex_val(hex[i * 2]);
        int lo = hex_val(hex[i * 2 + 1]);
        
        if (hi < 0 || lo < 0) return -1; // Invalid char
        
        buf[i] = (hi << 4) | lo;
    }
    return 0;
}

// --- Logic Adaptation ---

// Adapted directly from your print_b85 function
void encode_b85_and_print(const uint8_t *buf, int n) {
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

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <hex_string>\n", argv[0]);
        return 1;
    }

    const char *hex_str = argv[1];
    size_t bin_len;
    
    // Allocate buffer (Hex is 2 chars per byte, so buffer is half size)
    uint8_t *buf = malloc(strlen(hex_str) / 2 + 1);
    if (!buf) return 1;

    if (hex_to_bytes(hex_str, buf, &bin_len) != 0) {
        fprintf(stderr, "Error: Invalid hex string (must be even length and valid hex chars)\n");
        free(buf);
        return 1;
    }

    encode_b85_and_print(buf, (int)bin_len);
    printf("\n");

    free(buf);
    return 0;
}