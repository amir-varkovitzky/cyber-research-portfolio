
/*
 * udp.c
 * UDP helpers
 */

#include "udp.h"
#include "util.h"
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>

/*
 * Create a UDP server socket bound to bind_ip:port.
 * Returns file descriptor on success, -1 on error.
 */
int udp_server_socket(const char *bind_ip, unsigned short port)
{
    printf("[debug] Creating UDP server socket on %s:%u\n", bind_ip ? bind_ip : "<any>", port);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    int one = 1;
    struct sockaddr_in sa = {0};
    if (fd < 0)
    {
        perror("socket udp");
        return -1;
    }
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, (socklen_t)sizeof(one));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = bind_ip ? inet_addr(bind_ip) : INADDR_ANY;
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
    {
        perror("bind udp");
        close(fd);
        return -1;
    }
    (void)set_nonblock(fd);
    printf("[debug] Created UDP server socket: fd=%d\n", fd);
    return fd;
}

/*
 * Create a UDP client socket.
 * Returns file descriptor on success, -1 on error.
 */
int udp_client_socket(void)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        perror("socket udp client");
        return -1;
    }
    (void)set_nonblock(fd);
    printf("[debug] Created UDP client socket: fd=%d\n", fd);
    return fd;
}

/*
 * Send UDP packet to destination.
 */
ssize_t udp_sendto(int fd, const void *buf, size_t len, const struct sockaddr_in *dst)
{
    printf("[debug] Sending UDP packet to %s:%u\n",
           inet_ntoa(dst->sin_addr), ntohs(dst->sin_port));
    return sendto(fd, buf, len, 0, (const struct sockaddr *)dst, (socklen_t)sizeof(*dst));
}

/*
 * Receive UDP packet from source.
 */
ssize_t udp_recvfrom(int fd, void *buf, size_t len, struct sockaddr_in *src)
{
    socklen_t sl = (socklen_t)sizeof(*src);
    return recvfrom(fd, buf, len, 0, (struct sockaddr *)src, &sl);
}