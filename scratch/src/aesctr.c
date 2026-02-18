#include "aesctr.h"
#include <mbedtls/aes.h>
#include <string.h>
static void inc_be32(uint8_t ctr[16]) { for (int i = 15; i >= 12; i--) if (++ctr[i]) break; }
void aes_encrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16])
{
    mbedtls_aes_context ctx; mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, 128);
    mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, in, out);
    mbedtls_aes_free(&ctx);
}
void aes_ctr_encrypt(const uint8_t key[16], const uint8_t iv[12], const uint8_t *pt, size_t len, uint8_t *ct)
{
    uint8_t counter[16] = {0}; memcpy(counter, iv, 12); counter[15] = 1;
    size_t off = 0; uint8_t stream[16], block[16];
    while (off < len) {
        aes_encrypt_block(key, counter, stream);
        size_t chunk = (len - off) < 16 ? (len - off) : 16;
        memcpy(block, pt + off, chunk);
        for (size_t i = 0; i < chunk; i++) ct[off + i] = block[i] ^ stream[i];
        off += chunk; inc_be32(counter);
    }
}