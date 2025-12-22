/*
 * udp.h - UDP Socket Wrappers
 *
 * Provides definitions for UDP client and server socket operations.
 *
 * Usage:
 *   1. udp_server_socket(): Bind to a port for listening.
 *   2. udp_client_socket(): Open an unbound socket for sending.
 *   3. udp_sendto()/udp_recvfrom(): Wrappers for standard socket I/O.
 */

#ifndef UDP_H
#define UDP_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <stddef.h>
#include <sys/types.h>

/**
 * @brief Creates and binds a UDP socket.
 * @param bind_ip IP address to bind to (e.g., "0.0.0.0").
 * @param port Port number to bind.
 * @returns Socket file descriptor, or -1 on error.
 */
int udp_server_socket(const char *bind_ip, unsigned short port);

/**
 * @brief Creates an unbounded UDP socket.
 * @returns Socket file descriptor, or -1 on error.
 */
int udp_client_socket(void);

/**
 * @brief Sends a UDP packet to a destination.
 * @param fd Socket file descriptor.
 * @param buf Data buffer.
 * @param len Data length.
 * @param dst Destination address.
 * @returns Bytes sent, or -1 on error.
 */
ssize_t udp_sendto(int fd, const void *buf, size_t len, const struct sockaddr_in *dst);

/**
 * @brief Receives a UDP packet.
 * @param fd Socket file descriptor.
 * @param buf Data buffer.
 * @param len Buffer capacity.
 * @param src Pointer to store sender address.
 * @returns Bytes received, or -1 on error.
 */
ssize_t udp_recvfrom(int fd, void *buf, size_t len, struct sockaddr_in *src);

#endif /* UDP_H */