
/*
 * vpn_client.c
 * VPN client for Linux (TUN + UDP + AES-256-GCM)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include "../common/tun.h"
#include "../common/udp.h"
#include "../common/aead.h"
#include "../common/proto.h"
#include "../common/packet.h"
#include "../common/util.h"

#define MAXPKT (65536U)

/* Global running flag */
static volatile bool running = true;

static void handle_signal(int sig)
{
    (void)sig;
    running = false;
}

/*
 * Perform handshake with server to get client ID and virtual IP.
 * Returns 0 on success, -1 on failure.
 */
static int handshake(int udp_fd, struct sockaddr_in *srv, const uint8_t *psk, uint32_t *my_id, uint32_t *my_virt_ip)
{
    uint64_t send_ctr = 1U;
    uint8_t outbuf[MAXPKT], inbuf[MAXPKT], plain[MAXPKT];
    hello_t he;
    struct pollfd pfd;
    int retries = 5;
    
    he.want_id = htonl(0U);
    pfd.fd = udp_fd;
    pfd.events = POLLIN;

    while (running && retries > 0)
    {
        size_t hlen = avpn_build_encrypted(outbuf, sizeof(outbuf), (uint8_t)MSG_HELLO,
                                           0U, send_ctr++, psk,
                                           (const uint8_t *)&he, sizeof(he));
        if (hlen == 0)
        {
            fprintf(stderr, "[error] Failed to build handshake packet\n");
            return -1;
        }
        if (udp_sendto(udp_fd, outbuf, hlen, srv) < 0)
        {
            fprintf(stderr, "[error] Failed to send handshake packet\n");
            /* Don't return -1 immediately, retry */
        }
        else
        {
            printf("[info] Sent handshake request (attempt %d/5)...\n", 6 - retries);
        }

        /* Wait for response with timeout */
        int poll_res = poll(&pfd, 1, 2000); /* 2 seconds timeout */
        if (poll_res < 0)
        {
            if (!running) return -1;
            perror("poll");
            return -1;
        }
        else if (poll_res > 0)
        {
            if (pfd.revents & POLLIN)
            {
                struct sockaddr_in src;
                ssize_t r = udp_recvfrom(udp_fd, inbuf, sizeof(inbuf), &src);
                if (r > 0)
                {
                    size_t plen = 0U;
                    uint32_t cid = 0U;
                    uint64_t ctr = 0U;
                    if (avpn_open_encrypted(inbuf, (size_t)r, (uint8_t)MSG_ASSIGN,
                                            &cid, psk, plain, &plen, &ctr) == 0)
                    {
                        if (plen < sizeof(assign_t))
                        {
                            fprintf(stderr, "[error] Invalid ASSIGN packet size\n");
                            continue;
                        }
                        const assign_t *asg = (const assign_t *)plain;
                        if (my_id)
                            *my_id = cid;
                        if (my_virt_ip)
                            *my_virt_ip = ntohl(asg->assigned_ip);
                        printf("[info] Received ASSIGN: id=%u, virt_ip=%u\n", cid, ntohl(asg->assigned_ip));
                        return 0;
                    }
                }
            }
        }
        else
        {
            printf("[info] Timed out waiting for response.\n");
        }
        retries--;
    }
    
    return -1;
}

/*
 * Main VPN packet loop: poll TUN and UDP, encrypt/decrypt and forward packets.
 */
static void vpn_loop(int tun_fd, int udp_fd, struct sockaddr_in *srv, const uint8_t *psk, uint32_t my_id)
{
    uint64_t send_ctr = 2U;
    uint8_t outbuf[MAXPKT], inbuf[MAXPKT], plain[MAXPKT];
    struct pollfd pfds[2];
    pfds[0].fd = tun_fd;
    pfds[0].events = POLLIN;
    pfds[1].fd = udp_fd;
    pfds[1].events = POLLIN;
    
    while (running)
    {
        if (poll(pfds, 2, 1000) < 0)
        {
            if (!running) break;
            perror("poll");
            break;
        }
        if (pfds[0].revents & POLLIN)
        {
            ssize_t r1 = tun_read(tun_fd, plain, sizeof(plain));
            if (r1 > 0)
            {
                size_t pkt = avpn_build_encrypted(outbuf, sizeof(outbuf), (uint8_t)MSG_DATA,
                                                  my_id, send_ctr++, psk,
                                                  plain, (size_t)r1);
                if (pkt == 0)
                {
                    fprintf(stderr, "[error] Failed to build encrypted packet\n");
                    continue;
                }
                if (udp_sendto(udp_fd, outbuf, pkt, srv) < 0)
                {
                    fprintf(stderr, "[error] Failed to send encrypted packet\n");
                }
                else
                {
                    printf("[debug] Sent encrypted packet to server (%zd bytes)\n", r1);
                }
            }
        }
        if (pfds[1].revents & POLLIN)
        {
            printf("[debug] UDP socket ready for reading\n");
            struct sockaddr_in src;
            ssize_t r2 = udp_recvfrom(udp_fd, inbuf, sizeof(inbuf), &src);
            if (r2 > 0)
                printf("[debug] Received UDP packet from %s:%u\n",
                       inet_ntoa(src.sin_addr), ntohs(src.sin_port));
            {
                size_t plen = 0U;
                uint32_t cid2 = 0U;
                uint64_t ctr2 = 0U;
                if (avpn_open_encrypted(inbuf, (size_t)r2, (uint8_t)MSG_DATA,
                                        &cid2, psk, plain, &plen, &ctr2) == 0)
                {
                    if (tun_write(tun_fd, plain, plen) < 0)
                    {
                        fprintf(stderr, "[error] Failed to write decrypted packet to TUN\n");
                    }
                    else
                    {
                        printf("[debug] Received encrypted packet from server (%zu bytes)\n", plen);
                    }
                }
            }
        }
    }
}

int main(int argc, char **argv)
{
    const char *server_ip;
    const char *psk_path;
    uint8_t psk[32];
    int tun_fd = -1, udp_fd = -1;
    struct sockaddr_in srv;
    uint32_t my_id = 0U, my_virt_ip = 0U;
    
    /* Signal handling */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    memset(&srv, 0, sizeof(srv));
    
    printf("[debug] Initializing VPN client\n");
    if (argc < 2)
    {
        fprintf(stderr, "usage: %s <SERVER_IP>\n", argv[0]);
        return 1;
    }
    server_ip = argv[1];
    psk_path = getenv("AVPN_PSK_FILE");
    if (!psk_path || strlen(psk_path) == 0)
    {
        fprintf(stderr, "[fatal] AVPN_PSK_FILE not set\n");
        return 1;
    }
    printf("[debug] Using PSK file: %s\n", psk_path);

    printf("[debug] Initializing AEAD\n");
    if (aead_init() != 0)
    {
        fprintf(stderr, "[fatal] aead_init failed\n");
        return 1;
    }
    if (!load_psk(psk_path, psk))
    {
        fprintf(stderr, "[fatal] PSK load failed\n");
        return 1;
    }
    printf("[debug] PSK loaded successfully\n");

    const char *ifname = getenv("AVPN_TUN");
    if (!ifname || *ifname == '\0')
    {
        ifname = "tun0";
    }
    tun_fd = tun_open(ifname);
    if (tun_fd < 0)
    {
        fprintf(stderr, "[fatal] tun_open failed\n");
        return 1;
    }
    printf("[debug] TUN interface %s opened successfully\n", ifname);

    printf("[debug] Creating UDP client socket\n");
    udp_fd = udp_client_socket();
    if (udp_fd < 0)
    {
        fprintf(stderr, "[fatal] udp_client_socket failed\n");
        close(tun_fd);
        return 1;
    }
    printf("[debug] UDP client socket created successfully: fd=%d\n", udp_fd);

    printf("[debug] Starting handshake with server %s\n", server_ip);
    srv.sin_family = AF_INET;
    srv.sin_port = htons((unsigned short)AVPN_PORT);
    if (inet_pton(AF_INET, server_ip, &srv.sin_addr) != 1)
    {
        fprintf(stderr, "[fatal] invalid server ip\n");
        close(udp_fd);
        close(tun_fd);
        return 1;
    }
    if (handshake(udp_fd, &srv, psk, &my_id, &my_virt_ip) != 0)
    {
        fprintf(stderr, "[fatal] handshake failed\n");
        close(udp_fd);
        close(tun_fd);
        return 1;
    }
    printf("[info] Handshake successful: my_id=%u, my_virt_ip=%u\n", my_id, my_virt_ip);

    vpn_loop(tun_fd, udp_fd, &srv, psk, my_id);
    
    printf("[info] Client shutting down\n");
    secure_memzero(psk, sizeof(psk));
    close(udp_fd);
    close(tun_fd);
    return 0;
}