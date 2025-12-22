/*
 * fsa_test.c - Test for Fixed Size Allocator
 */
 
#include "fsa.h"
#include <stdio.h> /* for printf */
#include <stdlib.h> /* for malloc, free */

#define BLOCK_SIZE 16
#define NUM_BLOCKS 10

int main(void)
{
    size_t pool_size = FSA_SuggestSize(BLOCK_SIZE, NUM_BLOCKS);
    void *pool = malloc(pool_size);
    void *blocks[NUM_BLOCKS];
    size_t i;
    size_t free_count;

    if (!pool)
    {
        printf("Memory allocation for pool failed!\n");
        return 1;
    }

    FSA_Init(pool, BLOCK_SIZE, NUM_BLOCKS);

    free_count = FSA_CountFree(pool);
    printf("Initial free blocks: %lu\n", (unsigned long)free_count);
    if (free_count != NUM_BLOCKS)
    {
        printf("Test failed: wrong initial free count\n");
        free(pool);
        return 1;
    }

    /* Allocate all blocks */
    for (i = 0; i < NUM_BLOCKS; ++i)
    {
        blocks[i] = FSA_Alloc(pool);
        if (!blocks[i])
        {
            printf("Test failed: allocation failed at %lu\n", (unsigned long)i);
            free(pool);
            return 1;
        }
    }

    free_count = FSA_CountFree(pool);
    printf("Free blocks after allocation: %lu\n", (unsigned long)free_count);
    if (free_count != 0)
    {
        printf("Test failed: free count after allocation\n");
        free(pool);
        return 1;
    }

    /* Allocating one more should return NULL */
    if (FSA_Alloc(pool) != NULL)
    {
        printf("Test failed: allocation should fail when full\n");
        free(pool);
        return 1;
    }

    /* Free some blocks */
    for (i = 0; i < NUM_BLOCKS / 2; ++i)
    {
        FSA_Free(pool, blocks[i]);
    }
    free_count = FSA_CountFree(pool);
    printf("Free blocks after partial free: %lu\n", (unsigned long)free_count);
    if (free_count != NUM_BLOCKS / 2)
    {
        printf("Test failed: free count after partial free\n");
        free(pool);
        return 1;
    }
    
    /* Allocate again */
    for (i = 0; i < NUM_BLOCKS / 2; ++i)
    {
        void *block = FSA_Alloc(pool);
        if (!block)
        {
            printf("Test failed: allocation failed after partial free at %lu\n", (unsigned long)i);
            free(pool);
            return 1;
        }
    }
    free_count = FSA_CountFree(pool);
    printf("Free blocks after reallocation: %lu\n", (unsigned long)free_count);
    if (free_count != 0)
    {
        printf("Test failed: free count after reallocation\n");
        free(pool);
        return 1;
    }
    
    /* Free all blocks */
    for (i = 0; i < NUM_BLOCKS; ++i)
    {
        FSA_Free(pool, blocks[i]);
    }

    free_count = FSA_CountFree(pool);
    printf("Free blocks after free: %lu\n", (unsigned long)free_count);
    if (free_count != NUM_BLOCKS)
    {
        printf("Test failed: free count after free\n");
        free(pool);
        return 1;
    }

    printf("All tests passed!\n");
    free(pool);
    return 0;
}
