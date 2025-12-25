#ifndef __PRIME_H__
#define __PRIME_H__

#include <openssl/bn.h>
#include <openssl/err.h>

int generate_prime_bytes(unsigned char *p_buf, int bits);

#endif /* #ifndef __PRIME_H__ */