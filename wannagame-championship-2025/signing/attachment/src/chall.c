// gcc base85.c chall.c prime.c rsa.c -o chall -lcrypto
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include "prime.h"
#include "rsa.h"
#include "base85.h"

struct __attribute__((packed)) variable {
    uint8_t msg[64];
    uint8_t N[384];
    uint8_t prime[3][128];
    uint8_t sig[384];
} v;

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);

    int choice;

    keygen(v.N, v.prime, 1024 * 3);
    printf("N = "); print_b85(v.N, sizeof(v.N));
    printf("\n");
    uint8_t target[64] = "1_d4r3_y0u_70_519n_7h15_3x4c7_51x7y_f0ur_by73_57r1n9_w17h_my_k3y";

    for (int i = 0; i <= 20; i++) {
        printf("Sign(0) or Verify(1): ");
        scanf("%d", &choice);
        
        int c; 
        while ((c = getchar()) != '\n' && c != EOF);
        
        switch (choice)
        {
        case 0:
            printf("Input your message in base85:\n");
            input_b85(v.msg, 64);
            while ((c = getchar()) != '\n' && c != EOF);

            if (!memcmp(v.msg, target, 64)) {
                printf("Nuh uh\n");
                return 0;
            }
            sign(v.msg, v.N, v.prime, v.sig);
            printf("sig = "); print_b85(v.sig, sizeof(v.sig));
            printf("\n");
            break;
        case 1:
            printf("Provide your signature in base85:\n");
            uint8_t check[384];
            input_b85(check, 384);
            while ((c = getchar()) != '\n' && c != EOF);

            if (verify(target, check, v.N)) {
                uint8_t flag[64];
                FILE *f_flag = fopen("flag", "r");
                flag[fread(flag, 1, sizeof flag - 1, f_flag)] = 0;
                printf("%s\n", flag);
                fclose(f_flag);
                return 0;
            } else {
                printf("Wrong !\n");
                return 0;
            }
            break;
        default:
            printf("Huh ?\n");
            return 0;
        }
    }
}

