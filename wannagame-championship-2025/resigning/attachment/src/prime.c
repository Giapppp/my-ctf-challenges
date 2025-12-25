#include <openssl/bn.h>
#include <openssl/err.h>

int generate_prime_bytes(unsigned char *p_buf, int bits) {
    BIGNUM *prime = NULL;
    int ret = 0;
    int bytes = bits / 8;

    if (!p_buf) return 0;
    prime = BN_new();
    if (prime == NULL) goto err;

    if (!BN_generate_prime_ex(prime, bits, 0, NULL, NULL, NULL)) {
        goto err;
    }

    if (BN_bn2binpad(prime, p_buf, bytes) <= 0) {
        goto err;
    }
    ret = 1;

err:
    if (prime) BN_free(prime);
    return ret;
}