#include <stdio.h>
#include <stdlib.h>
#include "ext2_parser.h"

int main(int argc, char **argv) {
    if (argc != 3) {
        printf("Usage: %s <image_file> <absolute_path>\n", argv[0]);
        printf("Example: %s ext2.img /home/user/file.txt\n", argv[0]);
        return 1;
    }

    ext2_t *fs = EXT2OpenFS(argv[1]);
    if (!fs) {
        printf("Error: Failed to open filesystem image '%s'.\n", argv[1]);
        return 1;
    }

    int inode = EXT2GetFileInode(fs, argv[2]);
    if (inode < 0) {
        printf("File not found: %s\n", argv[2]);
    } else {
        printf("File '%s' found at inode: %d\n", argv[2], inode);
        int size = EXT2GetFileSize(fs, inode);
        printf("Size: %d bytes\n", size);
        if (size > 0) {
            char *buf = malloc(size + 1);
            if (buf) {
                if (EXT2ReadBytes(fs, inode, buf, size)) {
                    buf[size] = '\0';
                    printf("Content:\n%s\n", buf);
                } else {
                    printf("Error: Failed to read file content.\n");
                }
                free(buf);
            } else {
                printf("Error: Memory allocation failed.\n");
            }
        }
    }

    EXT2CloseFS(fs);
    return 0;
}
