/*
 * ext2_parser.h - Ext2 Filesystem Parser API
 *
 * Provides read-only access to an Ext2 filesystem image.
 * Allows file lookup, reading, and metadata inspection.
 *
 * Usage:
 *   1. Call EXT2OpenFS() to open an image file.
 *   2. Use EXT2GetFileInode() to find files.
 *   3. Use EXT2ReadBytes() to read content.
 *   4. Call EXT2CloseFS() to cleanup.
 */

#ifndef EXT2_PARSER_H
#define EXT2_PARSER_H

#include <stddef.h> /* size_t */

/* Opaque handle for the filesystem instance */
typedef struct ext2 ext2_t;

/**
 * @brief Opens and parses the superblock of an Ext2 image.
 * @param device Path to the image file (e.g., "ext2.img").
 * @returns Handle to the filesystem, or NULL on failure.
 */
ext2_t *EXT2OpenFS(const char *device);

/**
 * @brief Closes the filesystem and frees resources.
 * @param fs Handle to the filesystem.
 * @returns 0 on success, -1 on failure.
 */
int EXT2CloseFS(ext2_t *fs);

/**
 * @brief Resolves an absolute path to an inode number.
 * @param fs Handle to the filesystem.
 * @param path Absolute path to the file (e.g., "/home/user/file.txt").
 * @returns Inode number, or -1 if not found.
 */
int EXT2GetFileInode(ext2_t *fs, const char *path);

/**
 * @brief Reads bytes from a file specified by inode.
 * @param fs Handle to the filesystem.
 * @param inode_num The inode number of the file.
 * @param buffer Destination buffer.
 * @param bytes_to_read Number of bytes to read.
 * @returns Pointer to the buffer, or NULL on failure.
 */
void *EXT2ReadBytes(const ext2_t *fs, int inode_num, void *buffer, size_t bytes_to_read);

/**
 * @brief Retrieves the size of a file.
 * @param fs Handle to the filesystem.
 * @param inode_num The inode number.
 * @returns File size in bytes, or -1 on failure.
 */
int EXT2GetFileSize(const ext2_t *fs, const int inode_num);

/**
 * @brief Modifies the mode (permissions) of a file inode.
 * @param fs Handle to the filesystem.
 * @param inode_num The inode number.
 * @param new_mode New mode bits.
 * @returns 0 on success, -1 on failure.
 */
int EXT2Chmod(ext2_t *fs, int inode_num, unsigned short new_mode);

#endif /* EXT2_PARSER_H */
