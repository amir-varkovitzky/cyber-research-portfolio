/*
 * aead.h - Authenticated Encryption (AES-GCM) Interface
 *
 * Provides a simplified interface for OpenSSL's AES-256-GCM operations.
 * Enforces use of 256-bit keys and GCM mode for confidentiality and integrity.
 *
 * Usage:
 *   1. aead_init(): Initialize the crypto library/context.
 *   2. aead_seal(): Encrypt plaintext with tag generation.
 *   3. aead_open(): Decrypt ciphertext with tag verification.
 */

#ifndef AEAD_H
#define AEAD_H

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Initialize the AEAD subsystem (e.g., load providers).
 * @returns 0 on success, -1 on failure.
 */
int aead_init(void);

/**
 * @brief Encrypts data using AES-256-GCM (Seal).
 * 
 * @param key32 32-byte AES key.
 * @param nonce12 12-byte IV/Nonce.
 * @param aad Additional Authenticated Data.
 * @param aad_len Length of AAD.
 * @param plain Input plaintext.
 * @param plain_len Length of plaintext.
 * @param out_cipher_and_tag Output buffer for ciphertext + tag.
 * @param out_len Pointer to store total output length.
 * @returns 0 on success, -1 on failure.
 */
int aead_seal(const uint8_t *key32, const uint8_t *nonce12,
              const uint8_t *aad, size_t aad_len,
              const uint8_t *plain, size_t plain_len,
              uint8_t *out_cipher_and_tag, size_t *out_len);

/**
 * @brief Decrypts data using AES-256-GCM (Open).
 * 
 * @param key32 32-byte AES key.
 * @param nonce12 12-byte IV/Nonce.
 * @param aad Additional Authenticated Data.
 * @param aad_len Length of AAD.
 * @param cipher_and_tag Input ciphertext + tag.
 * @param in_len Length of input.
 * @param out_plain Output buffer for plaintext.
 * @param out_plain_len Pointer to store plaintext length.
 * @returns 0 on success, -1 on failure (e.g. tag mismatch).
 */
int aead_open(const uint8_t *key32, const uint8_t *nonce12,
              const uint8_t *aad, size_t aad_len,
              const uint8_t *cipher_and_tag, size_t in_len,
              uint8_t *out_plain, size_t *out_plain_len);

#endif /* AEAD_H */