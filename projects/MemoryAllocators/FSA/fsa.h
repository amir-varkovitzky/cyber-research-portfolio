/*
 * fsa.h - Fixed Size Allocator (FSA) API
 *
 * Provides a fixed-size memory allocator with O(1) alloc/free operations.
 * Ideal for real-time systems requiring deterministic performance.
 *
 * Usage:
 *   1. Calculate required pool size using FSA_SuggestSize().
 *   2. Allocate the pool memory.
 *   3. Initialize with FSA_Init().
 *   4. Use FSA_Alloc() and FSA_Free().
 */

#ifndef FSA_H
#define FSA_H

#include <stddef.h> /* size_t */

/**
 * @brief Calculates the total memory size required for the pool.
 * @param block_size Size of each fixed-size block in bytes.
 * @param num_blocks Total number of blocks to manage.
 * @returns Total size in bytes required for the pool.
 */
size_t FSA_SuggestSize(size_t block_size, size_t num_blocks);

/**
 * @brief Initializes the FSA allocator on a pre-allocated memory pool.
 * @param pool Pointer to the start of the memory pool.
 * @param block_size Size of each block (must match SuggestSize).
 * @param num_blocks Number of blocks (must match SuggestSize).
 */
void FSA_Init(void *pool, size_t block_size, size_t num_blocks);

/**
 * @brief Allocates a fixed-size block from the pool.
 * @param pool Pointer to the initialized pool.
 * @returns Pointer to the allocated block, or NULL if pool is full.
 */
void *FSA_Alloc(void *pool);

/**
 * @brief Frees a block back to the pool.
 * @param pool Pointer to the initialized pool.
 * @param block Pointer to the block to free.
 */
void FSA_Free(void *pool, void *block);

/**
 * @brief Counts the number of free blocks remaining in the pool.
 * @param pool Pointer to the initialized pool.
 * @returns Number of free blocks.
 */
size_t FSA_CountFree(const void *pool);

#endif /* FSA_H */
