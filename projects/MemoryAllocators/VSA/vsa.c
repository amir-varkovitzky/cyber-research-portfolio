/*
 * This file implements the VSA logic. For API documentation and usage,
 * see vsa.h. Only implementation-specific and code-related comments are present here.
 */

#include "vsa.h"
#include <stdio.h> /* for printf */

#define WORD_SIZE (sizeof(size_t))
#define ALIGN(size) (((size) + (WORD_SIZE - 1)) & ~(WORD_SIZE - 1))

/* Internal block header: positive size = free, negative size = allocated */
typedef struct block_header
{
    long size; /* positive: free, negative: allocated */
} block_header_t;

/* Internal block footer: positive size = free, negative size = allocated */
typedef struct block_footer
{
    long size; /* footer is a mirror of the header, used for coalescing */
} block_footer_t;

vsa_t *VSAInit(void *mem, size_t size)
{
    size_t aligned_size = ALIGN(size);
    block_header_t *first;
    block_footer_t *footer;
    block_header_t *sentinel;

    if (aligned_size < sizeof(block_header_t) + sizeof(block_footer_t) + WORD_SIZE)
    {
        return NULL; /* Not enough space for even the smallest block */
    }
    first = (block_header_t *)mem;
    first->size = (long)(aligned_size - sizeof(block_header_t) - sizeof(block_footer_t));
    footer = (block_footer_t *)((char *)(first + 1) + (first->size));
    footer->size = first->size;

    /* Add a sentinel header at the end of the pool to mark the end */
    sentinel = (block_header_t *)((char *)footer + sizeof(block_footer_t));
    sentinel->size = 0;
    return (vsa_t *)first;
}

void *VSAAlloc(vsa_t *vsa, size_t size)
{
    block_header_t *block = (block_header_t *)vsa;
    size_t req_size = ALIGN(size);
    while (block->size != 0)
    {
        /* Check if block is free and large enough */
        if (block->size > 0 && (size_t)block->size >= req_size)
        {
            size_t remaining = (size_t)block->size - req_size;
            block_footer_t *new_footer;
            block_footer_t *footer;
            if (remaining >= sizeof(block_header_t) + sizeof(block_footer_t) + WORD_SIZE)
            {
                /* Split block: create a new free block after the allocated one */
                block_header_t *next = (block_header_t *)((char *)(block + 1) + req_size + sizeof(block_footer_t));
                next->size = (long)(remaining - sizeof(block_header_t) - sizeof(block_footer_t));
                new_footer = (block_footer_t *)((char *)(next + 1) + next->size);
                new_footer->size = next->size;
                block->size = -(long)req_size;
                footer = (block_footer_t *)((char *)(block + 1) + req_size);
                footer->size = block->size;
            }
            else
            {
                /* Allocate entire block (no split) */
                footer = (block_footer_t *)((char *)(block + 1) + (block->size > 0 ? block->size : -block->size));
                block->size = -block->size;
                footer->size = block->size;
            }
            return (void *)(block + 1);
        }
        /* Move to next block using header size and footer size */
        block = (block_header_t *)((char *)(block + 1) + (block->size > 0 ? block->size : -block->size) + sizeof(block_footer_t));
    }
    return NULL;
}

void VSAFree(void *block)
{
    block_header_t *header;
    block_footer_t *footer;
    long block_size;
    block_header_t *next;
    block_footer_t *next_footer;
    block_footer_t *prev_footer;
    block_header_t *prev_header;

    if (!block)
        return;

    header = (block_header_t *)block - 1;
    footer = (block_footer_t *)((char *)(header + 1) + (header->size > 0 ? header->size : -header->size));
    block_size = (header->size > 0 ? header->size : -header->size);
    header->size = block_size; /* Mark as free */
    footer->size = block_size;

    /* Coalesce with next block if free */
    next = (block_header_t *)((char *)footer + sizeof(block_footer_t));
    if (next->size > 0)
    {
        next_footer = (block_footer_t *)((char *)(next + 1) + next->size);
        header->size += sizeof(block_header_t) + sizeof(block_footer_t) + next->size;
        footer = next_footer;
        footer->size = header->size;
    }

    /* Coalesce with previous block if free */
    prev_footer = (block_footer_t *)((char *)header - sizeof(block_footer_t));
    if (prev_footer->size > 0)
    {
        prev_header = (block_header_t *)((char *)header - sizeof(block_footer_t) - prev_footer->size - sizeof(block_header_t));
        prev_header->size += sizeof(block_header_t) + sizeof(block_footer_t) + header->size;
        header = prev_header;
        /* Final footer update after coalescing */
        footer = (block_footer_t *)((char *)(header + 1) + header->size);
        footer->size = header->size;
    }
}

size_t VSAMaxFreeChunk(const vsa_t *vsa)
{
    const block_header_t *block = (const block_header_t *)vsa;
    size_t max = 0;
    while (block->size != 0)
    {
        if (block->size > 0 && (size_t)block->size > max)
        {
            max = (size_t)block->size;
        }
        /* Skip header + payload + footer to reach next block */
        block = (const block_header_t *)((const char *)(block + 1) + 
                 (block->size > 0 ? block->size : -block->size) + sizeof(block_footer_t));
    }
    return max;
}