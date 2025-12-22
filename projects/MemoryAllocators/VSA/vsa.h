/*
 * vsa.h - Variable Size Allocator (VSA) API
 *
 * Provides a variable-size memory allocator with O(1) free and coalescing.
 *
 * Usage:
 *   1. Allocate a memory pool (e.g., with malloc or on the stack).
 *   2. Call VSAInit() to initialize the allocator.
 *   3. Use VSAAlloc() and VSAFree() to manage memory within the pool.
 */

#ifndef VSA_H
#define VSA_H

#include <stddef.h> /* for size_t */

/* Opaque handle for the VSA allocator */
typedef void vsa_t;

/**
 * @brief Initializes the VSA allocator on a given memory block.
 * @param mem Pointer to the start of the memory pool.
 * @param size Size of the memory pool in bytes.
 * @returns Handle to the allocator, or NULL if the pool is too small.
 */
vsa_t *VSAInit(void *mem, size_t size);

/**
 * @brief Allocates a chunk of memory of at least 'size' bytes from the VSA.
 * @param vsa Handle to the allocator.
 * @param size Number of bytes to allocate.
 * @returns Pointer to the allocated memory, or NULL if not enough space.
 */
void *VSAAlloc(vsa_t *vsa, size_t size);

/**
 * @brief Frees a previously allocated chunk. O(1) coalescing with neighbors.
 * @param block Pointer returned by VSAAlloc.
 */
void VSAFree(void *block);

/**
 * @brief Returns the size of the largest available chunk that can be allocated.
 * @param vsa Handle to the allocator.
 * @returns Size of the largest free chunk in bytes.
 */
size_t VSAMaxFreeChunk(const vsa_t *vsa);

#endif /* VSA_H */
