#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "utils.h"
#include "gf.h"
#include "ghash.h"
#include "aesctr.h"

static void print_hex(const char *label, const uint8_t *buf, size_t n)
{
    printf("%s", label);
    for (size_t i = 0; i < n; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

static void test_aes_gcm(void)
{
    /* Same key/nonce/plaintext as demo (mbedTLS GCM) */
    const uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    const uint8_t nonce[12] = {0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,0xaa,0xab};
    const uint8_t plaintext[] = "Hello World!";
    const size_t len = strlen((const char *)plaintext);

    uint8_t ciphertext[64] = {0};
    uint8_t tag[16] = {0};
    uint8_t decrypted[64] = {0};

    printf("AES-GCM Encryption/Decryption (our implementation)\n");

    /* Encrypt */
    aes_gcm_encrypt(key, nonce, NULL, 0, plaintext, len, ciphertext, tag);

    printf("PT:  %s\n", plaintext);
    print_hex("CT: ", ciphertext, len);
    print_hex("TAG: ", tag, 16);

    /* Decrypt and verify tag */
    if (aes_gcm_decrypt(key, nonce, NULL, 0, ciphertext, len, tag, decrypted) != 0) {
        printf("Decryption/verification failed!\n");
        return;
    }

    decrypted[len] = '\0';
    printf("DEC: %s\n", decrypted);
}

int main(void)
{
    test_aes_gcm();
    return 0;
}