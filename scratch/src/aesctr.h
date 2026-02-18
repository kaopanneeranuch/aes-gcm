#ifndef AESCTR_H
#define AESCTR_H
#include <stdint.h>
#include <stddef.h>
void aes_encrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);
void aes_ctr_encrypt(const uint8_t key[16], const uint8_t iv[12], const uint8_t *pt, size_t len, uint8_t *ct);
#endif