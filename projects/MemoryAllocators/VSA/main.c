/*
 * vsa_test.c - Test for Variable Size Allocator (VSA)
 */
 
#include "vsa.h"
#include <stdio.h>  /* for printf */
#include <stdlib.h> /* for malloc, free */

#define POOL_SIZE 256

int main(void)
{
    void *pool = malloc(POOL_SIZE);
    vsa_t *vsa = VSAInit(pool, POOL_SIZE);
    void *a = NULL, *b = NULL, *c = NULL;
    size_t max_chunk = 0;
    void *too_big = NULL;
    void *all = NULL;

    if (!pool)
    {
        printf("malloc for pool failed!\n");
        return 1;
    }
    if (!vsa)
    {
        printf("VSAInit failed!\n");
        free(pool);
        return 1;
    }

    max_chunk = VSAMaxFreeChunk(vsa);
    printf("Initial max free chunk: %lu\n", (unsigned long)max_chunk);

    /* Allocate three blocks of different sizes */
    a = VSAAlloc(vsa, 32); /* Real size will be aligned and include header/footer */
    b = VSAAlloc(vsa, 48);
    c = VSAAlloc(vsa, 16);

    printf("Allocated a: %p, b: %p, c: %p\n", a, b, c);
    max_chunk = VSAMaxFreeChunk(vsa);
    printf("Max free chunk after allocations: %lu\n", (unsigned long)max_chunk);

    /* Free the middle block and check coalescing */
    VSAFree(b);
    max_chunk = VSAMaxFreeChunk(vsa);
    printf("Max free chunk after freeing b: %lu\n", (unsigned long)max_chunk);

    /* Free the first block and check coalescing */
    VSAFree(a);
    max_chunk = VSAMaxFreeChunk(vsa);
    printf("Max free chunk after freeing a: %lu\n", (unsigned long)max_chunk);

    /* Free the last block and check if all is coalesced */
    VSAFree(c);
    max_chunk = VSAMaxFreeChunk(vsa);
    printf("Max free chunk after freeing c: %lu\n", (unsigned long)max_chunk);

    /* Try to allocate a block larger than possible */
    too_big = VSAAlloc(vsa, POOL_SIZE);
    printf("Allocation of too large block: %s\n", too_big ? "succeeded (error)" : "failed (expected)");

    /* Allocate the entire pool in one go */
    all = VSAAlloc(vsa, max_chunk);
    printf("Allocation of max chunk: %s\n", all ? "succeeded" : "failed");
    if (all)
    {
        VSAFree(all);
    }

    /* The max free chunk should now be the entire pool size */
    max_chunk = VSAMaxFreeChunk(vsa);
    printf("Max free chunk after freeing all: %lu\n", (unsigned long)max_chunk);

    printf("All VSA tests completed.\n");
    free(pool);
    return 0;
}
