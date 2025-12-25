#include <stdio.h>
#include <stdint.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <assert.h>
#include "prime.h"
#include "rsa.h"

void keygen(uint8_t N[384], uint8_t prime[3][128], int nbits) {
    assert(nbits % 3 == 0);

    BIGNUM *bn_N, *bn_prime[3];
    BN_CTX *ctx = BN_CTX_new();
    int pbits = nbits / 3;

    bn_N = BN_new();
    BN_set_word(bn_N, 1);

    for (int i = 0; i < 3; i++) {
        bn_prime[i] = BN_new();
        generate_prime_bytes(prime[i], pbits);
        BN_bin2bn(prime[i], 128, bn_prime[i]);
        BN_mul(bn_N, bn_N, bn_prime[i], ctx);
    }

    BN_bn2binpad(bn_N, N, 384);

    BN_free(bn_N);
    for (int i = 0; i < 3; i++) {
        BN_free(bn_prime[i]);
    }
    BN_CTX_free(ctx);
}

void sign(uint8_t msg[32], uint8_t N[384], uint8_t prime[3][128], uint8_t sig[384]) {
    uint8_t hmsg[32];
    int i, j;

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *bn_hmsg = BN_new();
    BIGNUM *bn_N = BN_new();
    BIGNUM *bn_e = BN_new();
    BIGNUM *bn_sig = BN_new();
    BIGNUM *ONE = BN_new();
    BIGNUM *bn_prime[3], *bn_d[3], *bn_phi_prime[3], *bn_hmsg_prime[3];

    BN_set_word(ONE, 1);

    BN_bin2bn(N, 384, bn_N);

    BN_set_word(bn_e, 0x10001);

    SHA256(msg, 32, hmsg);
    BN_bin2bn(hmsg, 32, bn_hmsg);

    for (i = 0; i < 3; i++) {
        bn_prime[i] = BN_new();
        bn_d[i] = BN_new();
        bn_phi_prime[i] = BN_new();
        bn_hmsg_prime[i] = BN_new();

        BN_bin2bn(prime[i], 128, bn_prime[i]);
        BN_sub(bn_phi_prime[i], bn_prime[i], ONE);
        BN_mod_inverse(bn_d[i], bn_e, bn_phi_prime[i], ctx);
        BN_mod_exp(bn_hmsg_prime[i], bn_hmsg, bn_d[i], bn_prime[i], ctx);
    }

    BIGNUM *y[3], *z[3];
    BN_zero(bn_sig);

    for (i = 0; i < 3; i++) {
        y[i] = BN_new();
        BN_set_word(y[i], 1);

        for (j = 0; j < 3; j++) {
            if (i != j) {
                BN_mul(y[i], y[i], bn_prime[j], ctx);
            }
        }

        z[i] = BN_new();
        BN_mod_inverse(z[i], y[i], bn_prime[i], ctx);

        BN_mul(y[i], y[i], z[i], ctx);
        BN_mul(bn_hmsg_prime[i], y[i], bn_hmsg_prime[i], ctx);
        BN_add(bn_sig, bn_sig, bn_hmsg_prime[i]);
    }

    BN_mod(bn_sig, bn_sig, bn_N, ctx);
    BN_bn2binpad(bn_sig, sig, 384);

    BN_free(bn_hmsg);
    BN_free(bn_N);
    BN_free(bn_e);
    BN_free(bn_sig);
    BN_free(ONE);
    for (i = 0; i < 3; i++) {
        BN_free(bn_prime[i]);
        BN_free(bn_d[i]);
        BN_free(bn_phi_prime[i]);
        BN_free(bn_hmsg_prime[i]);
        BN_free(y[i]);
        BN_free(z[i]);
    }
    BN_CTX_free(ctx);
}

int verify(uint8_t msg[64], uint8_t sig[384], uint8_t prime[3][128]) {
    uint8_t hmsg[32];
    
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *bn_hmsg = BN_new();
    BIGNUM *bn_N = BN_new();
    BIGNUM *bn_sig = BN_new();
    BIGNUM *bn_e = BN_new();
    BIGNUM *check = BN_new();
    BIGNUM *bn_prime[3];

    SHA256(msg, 64, hmsg);
    BN_bin2bn(hmsg, 32, bn_hmsg);
    
    BN_set_word(bn_e, 0x10001);
    BN_bin2bn(sig, 384, bn_sig);
    BN_set_word(bn_N, 1);

    for (int i = 0; i < 3; i++) {
        bn_prime[i] = BN_new();
        BN_bin2bn(prime[i], 128, bn_prime[i]);
        BN_mul(bn_N, bn_N, bn_prime[i], ctx);
    }
    
    BN_mod_exp(check, bn_sig, bn_e, bn_N, ctx);
    
    int ret = 0;
    if (BN_cmp(check, bn_hmsg) == 0) {
        ret = 1;
    } else {
        ret = 0;
    }

    BN_free(bn_hmsg);
    BN_free(bn_N);
    BN_free(bn_sig);
    BN_free(bn_e);
    BN_free(check);
    BN_CTX_free(ctx);

    return ret;
}