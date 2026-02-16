#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <string.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/aes.h>

int main(void)
{
    Aes aes;
    unsigned char key[32];       /* 256-bit key */
    unsigned char iv[12];        /* 96-bit IV */
    unsigned char plaintext[64];
    unsigned char ciphertext[64];
    unsigned char authTag[16];
    int ret;

    memset(key, 0x01, sizeof(key));
    memset(iv, 0x02, sizeof(iv));
    memset(plaintext, 0x03, sizeof(plaintext));

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) {
        printk("wc_AesInit failed: %d\n", ret);
        return ret;
    }

    ret = wc_AesGcmSetKey(&aes, key, sizeof(key));
    if (ret != 0) {
        printk("wc_AesGcmSetKey failed: %d\n", ret);
        wc_AesFree(&aes);
        return ret;
    }

    ret = wc_AesGcmEncrypt(&aes, ciphertext, plaintext, sizeof(plaintext),
                           iv, sizeof(iv), authTag, sizeof(authTag), NULL, 0);
    if (ret != 0) {
        printk("wc_AesGcmEncrypt failed: %d\n", ret);
    } else {
        printk("AES-GCM encryption succeeded!\n");
    }

    wc_AesFree(&aes);
    return 0;
}