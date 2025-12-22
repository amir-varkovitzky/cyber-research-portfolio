/*
 * fsa.c - Fixed Size Allocator implementation
 */
 
#include "fsa.h"

/* Alignment macro: round up to nearest multiple of sizeof(void*) */
#define ALIGN_WORD(x) (((x) + sizeof(void*) - 1) & ~(sizeof(void*) - 1))

struct FSA_Pool
{
    void *free_list; /* Pointer to the first free block */
    size_t block_size; /* Size of each block */
    size_t num_blocks; /* Total number of blocks in the pool */
};

/* Suggest the total size needed for the pool */
size_t FSA_SuggestSize(size_t block_size, size_t num_blocks)
{
    size_t real_block_size = ALIGN_WORD(block_size > sizeof(void*) ? block_size : sizeof(void*));
    return sizeof(struct FSA_Pool) + real_block_size * num_blocks;
}

/* Initialize the pool */
void FSA_Init(void *pool, size_t block_size, size_t num_blocks)
{
    char *mem = (char *)pool; /* A pointer to the memory pool */
    struct FSA_Pool *header = (struct FSA_Pool *)mem; /* Header for the pool */
    size_t i;
    size_t real_block_size = ALIGN_WORD(block_size > sizeof(void*) ? block_size : sizeof(void*));
    char *block_start = mem + sizeof(struct FSA_Pool); /* Start of the block memory is after the header, which holds metadata */
    char *block = block_start;

    header->block_size = real_block_size;
    header->num_blocks = num_blocks;
    header->free_list = (num_blocks > 0) ? block_start : NULL;

    /* Initialize the free list */
    for (i = 0; i < num_blocks; ++i)
    {
        char *next = (i + 1 < num_blocks) ? (block + real_block_size) : NULL;
        *(void **)block = next;
        block += real_block_size;
    }
}

/* Allocate a block */
void *FSA_Alloc(void *pool)
{
    struct FSA_Pool *header = (struct FSA_Pool *)pool;
    void *block = header->free_list;
    if (block)
    {
        header->free_list = *(void **)block;
    }
    return block;
}

/* Free a block */
void FSA_Free(void *pool, void *block)
{
    struct FSA_Pool *header = (struct FSA_Pool *)pool;
    *(void **)block = header->free_list;
    header->free_list = block;
}

/* Count free blocks */
size_t FSA_CountFree(const void *pool)
{
    const struct FSA_Pool *header = (const struct FSA_Pool *)pool;
    size_t count = 0;
    void *block = header->free_list;
    while (block)
    {
        ++count;
        block = *(void **)block;
    }
    return count;
}
