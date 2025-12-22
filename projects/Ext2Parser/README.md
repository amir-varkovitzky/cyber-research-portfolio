# Ext2 Filesystem Parser

A user-space tool to parse and explore Ext2 filesystem images. This project demonstrates understanding of disk structures, inodes, and file allocation.

## Usage

```bash
gcc -o ext2_parser main.c ext2_parser.c
./ext2_parser ext2.img <path_to_file>
```

## Structure
- `ext2_parser.c`: Main source code.
- `verify_ext2.sh`: Automated test script that creates and parses a clean Ext2 image.

## Verification
You can verify the parser functionality by running the included script (requires `e2fsprogs`):
```bash
./verify_ext2.sh
```

## Note on Filesystem Compatibility
This tool is strictly an **Ext2** parser. It supports:
- Direct Block Addressing
- Indirect Block Addressing (Singly Indirect)

It **does not support** Ext4 features such as **Extents**. If you attempt to parse a file on an Ext4 partition (even if mounted as ext2), it may fail if the file uses extents. The tool will warn you if it detects the Ext4 Extents flag.
