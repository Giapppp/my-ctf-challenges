#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// --- Original Constants & Globals ---

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

// --- Logic Adaptation ---

// Decodes a base85 string into a binary buffer
// Returns the length of the binary data
size_t decode_b85_string(const char *input, uint8_t *output) {
    size_t in_len = strlen(input);
    size_t out_idx = 0;
    size_t i = 0;
    
    // Process input until we run out of characters
    while (i < in_len) {
        uint8_t b[5];
        int chunk_len = 0;

        // Try to grab 5 characters (or fewer if we hit end of string)
        for (int k = 0; k < 5; k++) {
            if (i < in_len) {
                b[k] = BASE85_INV_ALPHABET[(uint8_t)input[i++]];
                chunk_len++;
            } else {
                // Pad with 'u' (value 84) as per your implementation
                b[k] = 84; 
            }
        }

        // Perform the math (Chunk accumulation)
        uint32_t chunk = b[0];
        chunk = chunk * 85 + b[1];
        chunk = chunk * 85 + b[2];
        chunk = chunk * 85 + b[3];
        chunk = chunk * 85 + b[4];

        // Determine how many bytes to write based on input chunk length
        // Logic derived from your switch cases:
        // 5 chars in -> 4 bytes out
        // 4 chars in -> 3 bytes out
        // 3 chars in -> 2 bytes out
        // 2 chars in -> 1 byte out
        int bytes_to_write = chunk_len - 1;

        if (bytes_to_write >= 1) output[out_idx++] = (chunk >> 24) & 0xFF;
        if (bytes_to_write >= 2) output[out_idx++] = (chunk >> 16) & 0xFF;
        if (bytes_to_write >= 3) output[out_idx++] = (chunk >> 8)  & 0xFF;
        if (bytes_to_write >= 4) output[out_idx++] = (chunk >> 0)  & 0xFF;
    }

    return out_idx;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <base85_string>\n", argv[0]);
        return 1;
    }

    const char *input_str = argv[1];
    size_t input_len = strlen(input_str);
    
    // Allocate buffer (Base85 is ~125% size of Binary, so Binary is ~80% of Base85)
    // We alloc full length just to be safe.
    uint8_t *buf = malloc(input_len + 5);
    if (!buf) return 1;

    size_t decoded_len = decode_b85_string(input_str, buf);

    // Print Hex String
    for (size_t i = 0; i < decoded_len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");

    free(buf);
    return 0;
}