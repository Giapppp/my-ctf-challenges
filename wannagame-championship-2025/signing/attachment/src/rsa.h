#ifndef __RSA_H__
#define __RSA_H__

#include <stdio.h>
#include <stdint.h>
#include <openssl/sha.h>

void keygen(uint8_t N[384], uint8_t prime[3][128], int nbits);
void sign(uint8_t msg[32], uint8_t N[384], uint8_t prime[3][128], uint8_t sig[384]);
int verify(uint8_t msg[32], uint8_t sig[384], uint8_t N[384]);

#endif /* #ifndef __RSA_H__ */