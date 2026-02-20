#include <mbedtls/gcm.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    mbedtls_gcm_context gcm;
    unsigned char key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    unsigned char nonce[12] = {0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,0xaa,0xab};
    unsigned char plaintext[] = "Hello World!";
    unsigned char ciphertext[32];
    unsigned char tag[16];
    unsigned char decrypted[32];
    int ret;

    printf("AES-GCM Encryption/Decryption Demo\n");

    // Initialize GCM context
    mbedtls_gcm_init(&gcm);

    // Set encryption key (128-bit)
    ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 128);
    if (ret != 0) {
        printf("Failed to set GCM key: %d\n", ret);
        return -1;
    }

    // Encrypt
    ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, 
                                      strlen((char *)plaintext), nonce, 12,
                                      NULL, 0, plaintext, ciphertext, 16, tag);
    if (ret != 0) {
        printf("Encryption failed: %d\n", ret);
        return -1;
    }

    printf("PT:  %s\n", plaintext);
    printf("CT: ");
    for (int i = 0; i < strlen((char *)plaintext); i++)
        printf("%02x", ciphertext[i]);
    printf("\n");
    printf("TAG: ");
    for (int i = 0; i < 16; i++)
        printf("%02x", tag[i]);
    printf("\n");

    // Decrypt and verify tag
    ret = mbedtls_gcm_auth_decrypt(&gcm,
                                    strlen((char *)plaintext), nonce, 12,
                                    NULL, 0, tag, 16,
                                    ciphertext, decrypted);
    if (ret != 0) {
        printf("Decryption/verification failed: %d\n", ret);
        return -1;
    }

    decrypted[strlen((char *)plaintext)] = '\0';
    printf("DEC:  %s\n", decrypted);

    mbedtls_gcm_free(&gcm);
    return 0;
}