#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "utils.h"
#include "gf.h"
#include "ghash.h"
#include "aesctr.h"

static int bytes_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}

static void print_hex(const char *label, const uint8_t *buf, size_t n)
{
    printf("%s", label);
    for (size_t i = 0; i < n; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

static void test_aes_ctr_encrypt_decrypt(void)
{
    const uint8_t key[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    const uint8_t iv[12]  = {
        0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,0xaa,0xab
    };

    const uint8_t plaintext[] = "Hello World!";
    const size_t len = sizeof(plaintext) - 1; // exclude '\0'

    uint8_t ciphertext[64] = {0};
    uint8_t decrypted[64]  = {0};

    /* Encrypt */
    aes_ctr_encrypt(key, iv, plaintext, len, ciphertext);

    /* Decrypt (CTR decrypt = CTR encrypt with same key/iv) */
    aes_ctr_encrypt(key, iv, ciphertext, len, decrypted);

    print_hex("CT: ", ciphertext, len);

    if (bytes_equal(plaintext, decrypted, len)) {
        decrypted[len] = '\0';
        printf("AES-CTR roundtrip: PASS\n");
        printf("PT: %s\n", plaintext);
        printf("DEC:%s\n", decrypted);
    } else {
        printf("AES-CTR roundtrip: FAIL\n");
    }
}

int main(void){
        uint8_t buf[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        uint64_t v = load_64(buf);
        uint8_t out[8];
        store_64(out, v);
        printf("roundtrip: ");
        for (int i = 0; i < 8; i++) printf("%02x", out[i]);
        printf("\n");

        // GF multiply test
        uint8_t X[16] = {0}; X[15] = 0x01; /* X = 1 */
        uint8_t Y[16] = {
            0x66,0xe9,0x4b,0xd4,0xef,0x8a,0x2c,0x3b,
            0x88,0x1f,0x52,0xa5,0x7a,0x4b,0x9b,0x9b
        };
        uint8_t Z[16];
        gf_mul(X, Y, Z);
        printf("gf_mul(X=1, Y) = ");
        for (int i = 0; i < 16; i++) printf("%02x", Z[i]);
        printf("\n");

        uint8_t key[16] = {0x00}; uint8_t zero[16] = {0}; uint8_t H[16];
        aes_encrypt_block(key, zero, H);
        printf("H = "); for (int i=0;i<16;i++) printf("%02x", H[i]); printf("\n");

        test_aes_ctr_encrypt_decrypt();

        return 0;
}