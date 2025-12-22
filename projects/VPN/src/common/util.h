/*
 * util.h - Common Utilities
 *
 * Provides helper functions for crypto, I/O, and memory handling.
 *
 * Usage:
 *   1. nonce_from_counter(): Generate a 12-byte nonce from a counter.
 *   2. load_psk(): Load a 32-byte key from a file.
 *   3. secure_memzero(): Wipe a memory buffer.
 *   4. set_nonblock(): Set a file descriptor to non-blocking mode.
 */

#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/**
 * @brief Generates a 12-byte nonce from a 64-bit counter.
 * @param ctr The counter value.
 * @param out12 Buffer to store the 12-byte nonce.
 */
void nonce_from_counter(uint64_t ctr, uint8_t out12[12]);

/**
 * @brief Loads a 32-byte Pre-Shared Key (PSK) from a file.
 * @param path Path to the key file.
 * @param out_key Buffer to store the 32-byte key.
 * @returns true on success, false on failure.
 */
bool load_psk(const char *path, uint8_t out_key[32]);

/**
 * @brief Securely zeroes out memory (prevents compiler optimization).
 * @param p Pointer to memory.
 * @param n Number of bytes to zero.
 */
void secure_memzero(void *p, size_t n);

/**
 * @brief Sets a file descriptor to non-blocking mode.
 * @param fd File descriptor.
 * @returns true on success, false on failure.
 */
bool set_nonblock(int fd);

#endif /* UTIL_H */