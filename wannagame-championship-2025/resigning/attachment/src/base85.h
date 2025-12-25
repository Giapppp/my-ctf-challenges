#ifndef __BASE85_H__
#define __BASE85_H__

#include <stdio.h>
#include <string.h>
#include <stdint.h>

void input_b85(uint8_t *buf, int n);
void print_b85(const uint8_t *buf, int n);

#endif /* #ifndef __BASE85_H__ */