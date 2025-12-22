/*
 * tun.h - TUN Device Interface
 *
 * Provides abstraction for opening and interacting with Linux TUN devices
 * for Layer 3 network packet injection and reading.
 *
 * Usage:
 *   1. tun_open(): Create/open a TUN interface (e.g., "tun0").
 *   2. tun_read()/tun_write(): Transfer packets between user space and kernel.
 */

#ifndef TUN_H
#define TUN_H

#include <stddef.h>
#include <sys/types.h>

/**
 * @brief Opens or creates a TUN interface.
 * 
 * Configures the interface as IFF_TUN | IFF_NO_PI (IP packets, no proto info).
 * 
 * @param ifname Name of the interface (e.g. "tun0").
 * @returns File descriptor on success, -1 on error.
 */
int tun_open(const char *ifname);

/**
 * @brief Reads an IP packet from the TUN interface.
 * @param fd TUN file descriptor.
 * @param buf Buffer to store the packet.
 * @param len Capacity of the buffer.
 * @returns Number of bytes read, or -1 on error.
 */
ssize_t tun_read(int fd, void *buf, size_t len);

/**
 * @brief Writes an IP packet to the TUN interface.
 * @param fd TUN file descriptor.
 * @param buf Buffer containing the packet.
 * @param len Length of the packet.
 * @returns Number of bytes written, or -1 on error.
 */
ssize_t tun_write(int fd, const void *buf, size_t len);

#endif /* TUN_H */