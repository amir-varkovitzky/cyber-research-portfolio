
/*
 * aead_openssl.c
 * AES-256-GCM authenticated encryption using OpenSSL EVP
 */

#include "aead.h"
#include <string.h>
#include <openssl/evp.h>

/*
 * Initialize AEAD subsystem (OpenSSL auto-init).
 * Returns 0 on success.
 */
int aead_init(void)
{
    return 0;
}

/**
 * @brief Encrypts plaintext using AES-256-GCM.
 *
 * @param key32 32-byte encryption key.
 * @param nonce12 12-byte nonce.
 * @param aad Additional authenticated data.
 * @param aad_len Length of AAD.
 * @param plain Pointer to the plaintext data.
 * @param plain_len Length of the plaintext data.
 * @param out Pointer to the output buffer for the ciphertext.
 * @param out_len Pointer to the variable to store the length of the ciphertext.
 * @return int 0 on success, -1 on error.
 */
int aead_seal(const uint8_t *key32, const uint8_t *nonce12,
              const uint8_t *aad, size_t aad_len,
              const uint8_t *plain, size_t plain_len,
              uint8_t *out, size_t *out_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, outlen = 0;
    unsigned char tag[16];
    if (!ctx)
        return -1;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto err;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1)
        goto err;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key32, nonce12) != 1)
        goto err;
    if (aad && aad_len)
    {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1)
            goto err;
    }
    if (EVP_EncryptUpdate(ctx, out, &len, plain, (int)plain_len) != 1)
        goto err;
    outlen += len;
    if (EVP_EncryptFinal_ex(ctx, out + outlen, &len) != 1)
        goto err;
    outlen += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1)
        goto err;
    memcpy(out + outlen, tag, 16);
    outlen += 16;
    *out_len = (size_t)outlen;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}
/**
 * @brief Decrypts ciphertext using AES-256-GCM.
 *
 * @param key32 32-byte encryption key.
 * @param nonce12 12-byte nonce.
 * @param aad Additional authenticated data.
 * @param aad_len Length of AAD.
 * @param in Pointer to the ciphertext data.
 * @param in_len Length of the ciphertext data.
 * @param out_plain Pointer to the output buffer for the plaintext.
 * @param out_plain_len Pointer to the variable to store the length of the plaintext.
 * @return int 0 on success, -1 on error.
 */
int aead_open(const uint8_t *key32, const uint8_t *nonce12,
              const uint8_t *aad, size_t aad_len,
              const uint8_t *in, size_t in_len,
              uint8_t *out_plain, size_t *out_plain_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, outlen = 0;
    size_t ct_len;
    if (!ctx)
        return -1;
    if (in_len < 16)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ct_len = in_len - 16;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto err;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1)
        goto err;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key32, nonce12) != 1)
        goto err;
    if (aad && aad_len)
    {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1)
            goto err;
    }
    if (EVP_DecryptUpdate(ctx, out_plain, &len, in, (int)ct_len) != 1)
        goto err;
    outlen += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)(in + ct_len)) != 1)
        goto err;
    if (EVP_DecryptFinal_ex(ctx, out_plain + outlen, &len) != 1)
        goto err;
    outlen += len;
    *out_plain_len = (size_t)outlen;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}