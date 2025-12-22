# Fixed Size Allocator (FSA)

A memory allocator designed for deterministic, O(1) allocation and deallocation of fixed-size blocks. Ideally suited for real-time systems or scenarios where memory fragmentation must be avoided.

## Features
- **O(1) Allocation/Free**: Constant time operations regardless of pool size.
- **No External Fragmentation**: Blocks are fixed size.
- **Minimal Overhead**: Uses a free-list embedded within the unallocated blocks.

## Usage

1.  **Calculate Size**: Use `FSA_SuggestSize(block_size, num_blocks)` to determine the required memory pool size.
2.  **Initialize**: Call `FSA_Init(pool, block_size, num_blocks)`.
3.  **Allocate**: Use `FSA_Alloc(pool)` to get a block.
4.  **Free**: Return blocks with `FSA_Free(pool, block)`.

## Example
```c
#include "fsa.h"
#include <stdlib.h>

#define BLOCK_SIZE 32
#define NUM_BLOCKS 100

void main() {
    size_t pool_size = FSA_SuggestSize(BLOCK_SIZE, NUM_BLOCKS);
    void *pool = malloc(pool_size);
    
    FSA_Init(pool, BLOCK_SIZE, NUM_BLOCKS);
    
    void *block = FSA_Alloc(pool);
    /* Use block... */
    FSA_Free(pool, block);
    
    free(pool);
}
```

## Compilation
```bash
gcc -o fsa_test main.c fsa.c
./fsa_test
```
