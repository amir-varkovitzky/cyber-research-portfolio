/**
 * @brief This is the implementation of the ext2_parser library.
 *
 * @author Amir Varkovitzky
 * @date 2025-06-23
 */

#include "ext2_parser.h"
#include "ext2_fs.h" /* ext2 filesystem structures */
#include <stdio.h>              /* for printf */
#include <stdlib.h>             /* for malloc, free */
#include <string.h>             /* for memset */
#include <unistd.h>             /* for close */
#include <fcntl.h>              /* for open */
#include <errno.h>              /* for errno */

#ifndef _GNU_SOURCE
static char *my_strdup(const char *s)
{
    size_t len = strlen(s) + 1;
    char *d = malloc(len);
    if (d == NULL)
        return NULL;
    memcpy(d, s, len);
    return d;
}
#define strdup my_strdup
#endif

#define EXT2_SUPERBLOCK_OFFSET 1024
#define EXT2_SUPERBLOCK_SIZE 1024
/*#define EXT2_BLOCK_SIZE(s) (EXT2_MIN_BLOCK_SIZE << (s)->s_log_block_size)*/
/*#define EXT2_INODE_SIZE(s) ((s)->s_inode_size)*/
/*#define EXT2_N_BLOCKS 15*/
/*#define EXT2_NDIR_BLOCKS 12*/

struct ext2
{
    int fd;
    struct ext2_super_block sb;
    unsigned int block_size;
    unsigned int inodes_per_group;
    unsigned int inode_size;
    unsigned int first_data_block;
    unsigned int group_desc_count;
    struct ext2_group_desc *group_desc;
};

/**
 * @brief Reads a block from the EXT2 filesystem.
 *
 * @param fs The EXT2 filesystem to read from.
 * @param block_num The block number to read.
 * @param buf The buffer to read the block into.
 * @return 0 on success, -1 on failure.
 */
static int read_block(const struct ext2 *fs, unsigned int block_num, void *buf)
{
    off_t offset = block_num * fs->block_size;
    if (lseek(fs->fd, offset, SEEK_SET) < 0)
        return -1;
    return read(fs->fd, buf, fs->block_size) == (ssize_t)fs->block_size ? 0 : -1;
}

/**
 * @brief Reads an inode from the EXT2 filesystem.
 *
 * @param fs The EXT2 filesystem to read from.
 * @param inode_num The inode number to read.
 * @param inode Pointer to the inode structure to fill.
 * @return 0 on success, -1 on failure.
 */
static int read_inode(const struct ext2 *fs, unsigned int inode_num, struct ext2_inode *inode)
{
    unsigned int group = (inode_num - 1) / fs->inodes_per_group;
    unsigned int index = (inode_num - 1) % fs->inodes_per_group;
    unsigned int inode_table_block = fs->group_desc[group].bg_inode_table;
    off_t offset = inode_table_block * fs->block_size + index * fs->inode_size;
    if (lseek(fs->fd, offset, SEEK_SET) < 0)
        return -1;
    printf("Reading inode %u from block %u, offset %lu\n", inode_num, inode_table_block, offset);
    return read(fs->fd, inode, sizeof(struct ext2_inode)) == sizeof(struct ext2_inode) ? 0 : -1;
}

/**
 * @brief Finds a directory entry by name in a directory inode.
 *
 * @param fs The EXT2 filesystem to search in.
 * @param dir_inode_num The inode number of the directory.
 * @param name The name of the entry to find.
 * @param out_inode Pointer to store the found inode number.
 * @return 0 on success, -1 if not found or on error.
 */
static int search_dir_block(const struct ext2 *fs, unsigned int block_num, const char *name, unsigned int *out_inode)
{
    char *block;
    unsigned int offset = 0;

    if (block_num == 0)
        return -1;

    block = malloc(fs->block_size);
    if (!block)
        return -1;

    if (read_block(fs, block_num, block) < 0)
    {
        free(block);
        return -1;
    }

    while (offset < fs->block_size)
    {
        struct ext2_dir_entry_2 *entry = (struct ext2_dir_entry_2 *)(block + offset);

        /* Break if rec_len is clearly invalid */
        if (entry->rec_len < 8 || offset + entry->rec_len > fs->block_size)
        {
            break;
        }

        if (entry->inode &&
            entry->name_len == strlen(name) &&
            memcmp(entry->name, name, entry->name_len) == 0)
        {
            *out_inode = entry->inode;
            free(block);
            return 0;
        }

        offset += entry->rec_len;
    }
    free(block);
    return -1;
}

static int find_dir_entry(const struct ext2 *fs, unsigned int dir_inode_num, const char *name, unsigned int *out_inode)
{
    struct ext2_inode dir_inode;
    int i;
    
    if (read_inode(fs, dir_inode_num, &dir_inode) < 0)
    {
        return -1;
    }
    
    /* Check for Ext4 Extents flag (0x80000) */
    if (dir_inode.i_flags & 0x80000)
    {
        printf("[WARN] Inode %u uses Ext4 Extents (flag 0x80000). This Ext2 parser cannot read it.\n", dir_inode_num);
        return -1;
    }

    /* 1. Search Direct Blocks (0-11) */
    for (i = 0; i < EXT2_NDIR_BLOCKS; ++i)
    {
        if (dir_inode.i_block[i] != 0) {
            /* printf("[DEBUG] Checking Direct Block %d (phy: %u)\n", i, dir_inode.i_block[i]); */
            if (search_dir_block(fs, dir_inode.i_block[i], name, out_inode) == 0)
                return 0;
        }
    }

    /* 2. Search Singly Indirect Block (12) */
    if (dir_inode.i_block[12])
    {
        uint32_t *indirect_block = malloc(fs->block_size);
        if (indirect_block)
        {
            if (read_block(fs, dir_inode.i_block[12], indirect_block) == 0)
            {
                unsigned int ptrs_per_block = fs->block_size / sizeof(uint32_t);
                unsigned int j;
                for (j = 0; j < ptrs_per_block; ++j)
                {
                    if (indirect_block[j] != 0)
                    {
                        if (search_dir_block(fs, indirect_block[j], name, out_inode) == 0)
                        {
                            free(indirect_block);
                            return 0;
                        }
                    }
                }
            }
            free(indirect_block);
        }
    }

    return -1;
}

ext2_t *EXT2OpenFS(const char *device)
{
    int fd;
    struct ext2_super_block sb;
    struct ext2 *fs;
    size_t desc_bytes;
    off_t desc_off;
    fd = open(device, O_RDWR);
    if (fd < 0)
        return NULL;
    if (lseek(fd, EXT2_SUPERBLOCK_OFFSET, SEEK_SET) < 0 ||
        read(fd, &sb, sizeof(sb)) != sizeof(sb) ||
        sb.s_magic != EXT2_SUPER_MAGIC)
    {
        close(fd);
        return NULL;
    }
    fs = calloc(1, sizeof(struct ext2));
    if (!fs)
    {
        close(fd);
        return NULL;
    }
    fs->fd = fd;
    fs->sb = sb;
    fs->block_size = EXT2_BLOCK_SIZE(&sb);
    fs->inodes_per_group = sb.s_inodes_per_group;
    fs->inode_size = EXT2_INODE_SIZE(&sb);
    fs->first_data_block = sb.s_first_data_block;
    fs->group_desc_count = (sb.s_blocks_count + sb.s_blocks_per_group - 1) / sb.s_blocks_per_group;
    desc_bytes = fs->group_desc_count * sizeof(struct ext2_group_desc);
    fs->group_desc = malloc(desc_bytes);
    if (!fs->group_desc)
    {
        close(fd);
        free(fs);
        return NULL;
    }
    desc_off = (sb.s_first_data_block + 1) * EXT2_BLOCK_SIZE(&sb);
    if (lseek(fd, desc_off, SEEK_SET) < 0 ||
        read(fd, fs->group_desc, desc_bytes) != (ssize_t)desc_bytes)
    {
        close(fd);
        free(fs->group_desc);
        free(fs);
        return NULL;
    }
    return fs;
}

int EXT2CloseFS(ext2_t *fs)
{
    if (!fs)
        return -1;
    close(fs->fd);
    free(fs->group_desc);
    free(fs);
    return 0;
}

int EXT2GetFileInode(ext2_t *fs, const char *path)
{
    unsigned int inode;
    char *path_copy;
    char *token;
    if (!fs || !path || path[0] != '/')
        return -1;
    inode = EXT2_ROOT_INO;
    path_copy = strdup(path);
    if (!path_copy)
        return -1;
    token = strtok(path_copy, "/");
    while (token)
    {
        if (find_dir_entry(fs, inode, token, &inode) < 0)
        {
            free(path_copy);
            return -1;
        }
        token = strtok(NULL, "/");
    }
    free(path_copy);
    return inode;
}

void *EXT2ReadBytes(const ext2_t *fs, int inode_num, void *buffer, size_t bytes_to_read)
{
    struct ext2_inode inode;
    size_t total_read;
    char *buf;
    int i;
    if (!fs || inode_num < 1 || !buffer)
        return NULL;
    if (read_inode(fs, inode_num, &inode) < 0)
        return NULL;
    total_read = 0;
    buf = buffer;
    for (i = 0; i < EXT2_NDIR_BLOCKS && total_read < bytes_to_read; ++i)
    {
        char *block;
        size_t to_copy;
        if (inode.i_block[i] == 0)
            break;
        block = malloc(fs->block_size);
        if (!block)
            return NULL;
        if (read_block(fs, inode.i_block[i], block) < 0)
        {
            free(block);
            return NULL;
        }
        to_copy = fs->block_size;
        if (total_read + to_copy > bytes_to_read)
            to_copy = bytes_to_read - total_read;
        memcpy(buf + total_read, block, to_copy);
        total_read += to_copy;
        free(block);
    }
    return buffer;
}

int EXT2GetFileSize(const ext2_t *fs, const int inode_num)
{
    struct ext2_inode inode;
    if (!fs || inode_num < 1)
        return -1;
    if (read_inode(fs, inode_num, &inode) < 0)
        return -1;
    return inode.i_size;
}

int EXT2Chmod(ext2_t *fs, int inode_num, unsigned short new_mode)
{
    struct ext2_inode inode;
    unsigned int group;
    unsigned int index;
    unsigned int inode_table_block;
    off_t offset;

    if (!fs || inode_num < 1)
        return -1;

    group = (inode_num - 1) / fs->inodes_per_group;
    index = (inode_num - 1) % fs->inodes_per_group;
    inode_table_block = fs->group_desc[group].bg_inode_table;
    offset = inode_table_block * fs->block_size + index * fs->inode_size;

    /* Read the inode from disk */
    if (lseek(fs->fd, offset, SEEK_SET) < 0)
        return -1;
    if (read(fs->fd, &inode, sizeof(inode)) != sizeof(inode))
        return -1;

    printf("Current inode mode: %o\n", inode.i_mode);
    /* Mask upper bits (file type), replace lower 12 bits (permissions) */
    inode.i_mode = (inode.i_mode & 0xF000) | (new_mode & 0x0FFF);
    printf("Updated inode mode: %o\n", inode.i_mode);

    /* Seek back and write the updated inode */
    if (lseek(fs->fd, offset, SEEK_SET) < 0)
    {
        printf("lseek failed\n");
        return -1;
    }
    if (write(fs->fd, &inode, sizeof(inode)) != sizeof(inode))
    {
        printf("write failed\n");
        return -1;
    }

    return 0;
}
