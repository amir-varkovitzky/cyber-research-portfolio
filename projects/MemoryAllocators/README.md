# Custom Memory Allocators

High-performance, manual memory management implementations for embedded systems and constrained environments.

## Components

### Fixed-Size Allocator (FSA)
- **Time Complexity**: O(1) for allocation and free.
- **Use Case**: Real-time systems where determinism is critical.
- **Mechanism**: Manages a pool of identical-sized blocks using an embedded free-list.

### Variable-Size Allocator (VSA)
- **Time Complexity**: O(n) or improved depending on defragmentation strategy.
- **Use Case**: General purpose dynamic memory allocation (like `malloc`).
- **Mechanism**: Uses block headers/footers for coalescing free chunks and reducing fragmentation.

## Usage
This project is divided into two independent modules. Please refer to their respective directories for detailed documentation and usage instructions:

- **[Fixed-Size Allocator (FSA)](./FSA/README.md)**: located in `FSA/`
- **[Variable-Size Allocator (VSA)](./VSA/README.md)**: located in `VSA/`

Each module contains its own headers, source code, and test suite.
