# Variable Size Allocator (VSA)

A memory allocator that supports variable-sized allocations with O(1) free and coalescing operations. It manages a given memory pool using an implicit free list with boundary tags.

## Features
- **Variable Size Allocation**: Request exactly the size you need.
- **O(1) Free & Coalescing**: Immediate merging of adjacent free blocks prevents fragmentation.
- **Boundary Tags**: Uses header and footer tags for efficient block management.

## Usage

1.  **Initialize**: Call `VSAInit(pool, pool_size)` with a pre-allocated memory block.
2.  **Allocate**: Use `VSAAlloc(vsa, size)` to request memory.
3.  **Free**: Use `VSAFree(block)` to release memory. **Note**: `VSAFree` does not require the pool pointer.
4.  **Maintenance**: `VSAMaxFreeChunk(vsa)` reports the largest allocatable block.

## Example
```c
#include "vsa.h"
#include <stdlib.h>

void main() {
    void *pool = malloc(1024);
    vsa_t *vsa = VSAInit(pool, 1024);
    
    void *ptr1 = VSAAlloc(vsa, 100);
    void *ptr2 = VSAAlloc(vsa, 200);
    
    VSAFree(ptr1); /* Automatically coalesces if adjacent space is free */
    
    free(pool);
}
```

## Compilation
```bash
gcc -o vsa_test main.c vsa.c
./vsa_test
```
