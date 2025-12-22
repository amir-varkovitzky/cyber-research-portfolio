/*
 * packet.h - Packet Handling API
 *
 * Provides functions to build and unwrap encrypted VPN packets.
 * Handles authenticated encryption (AES-256-GCM) and header construction.
 *
 * Usage:
 *   1. avpn_build_encrypted(): Encrypts plaintext and adds header.
 *   2. avpn_open_encrypted(): Validates header/tag and decrypts payload.
 */

#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <stddef.h>
#include "proto.h"

/**
 * @brief Constructs an encrypted VPN packet.
 * 
 * Encrypts the plaintext using the provided key and nonce counter, then
 * prepends the AVPN header.
 *
 * @param out Buffer to store the resulting packet.
 * @param out_cap Capacity of the output buffer.
 * @param type Message type (MSG_*).
 * @param client_id Client identifier.
 * @param send_ctr Monotonically increasing counter for nonce generation.
 * @param key32 32-byte AES key.
 * @param plain Plaintext payload.
 * @param plain_len Length of plaintext.
 * @returns Total size of the encrypted packet, or 0 on error.
 */
size_t avpn_build_encrypted(uint8_t *out, size_t out_cap,
                            uint8_t type, uint32_t client_id, uint64_t send_ctr,
                            const uint8_t *key32,
                            const uint8_t *plain, size_t plain_len);

/**
 * @brief Decrypts and validates an incoming VPN packet.
 * 
 * Checks magic, version, and type. Authenticates using GCM tag.
 *
 * @param in Input packet buffer.
 * @param in_len Length of input packet.
 * @param expected_type Expected message type (or 0 for ANY).
 * @param client_id_out Pointer to store the extracted client ID.
 * @param key32 32-byte AES key.
 * @param plain_out Buffer to store decrypted plaintext.
 * @param plain_len_out Pointer to store plaintext length.
 * @param nonce_ctr_out Pointer to store extracted nonce counter.
 * @returns 0 on success, -1 on failure/forgery.
 */
int avpn_open_encrypted(const uint8_t *in, size_t in_len,
                        uint8_t expected_type, uint32_t *client_id_out,
                        const uint8_t *key32,
                        uint8_t *plain_out, size_t *plain_len_out,
                        uint64_t *nonce_ctr_out);

#endif /* PACKET_H */