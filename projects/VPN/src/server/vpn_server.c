
/*
 * vpn_server.c
 * VPN server for Linux (TUN + UDP + AES-256-GCM)
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
#define MAXCLIENTS (64U)
#define VPN_SUBNET_H (0x0A080000U) /* 10.8.0.0 */

typedef struct
{
    bool used;
    uint32_t id;
    uint32_t virt_ip;        /* host order */
    struct sockaddr_in peer; /* last peer address */
    uint64_t send_ctr;
    uint64_t recv_high;
    uint64_t recv_window; /* 64-bit sliding window */
} client_t;

static client_t clients[MAXCLIENTS];
static uint8_t psk[32];

/* Find client by ID */
static client_t *find_by_id(uint32_t id)
{
    for (size_t i = 0; i < MAXCLIENTS; ++i)
        if (clients[i].used && clients[i].id == id)
            return &clients[i];
    return NULL;
}

/* Find client by virtual IP */
static client_t *find_by_virt(uint32_t vip)
{
    for (size_t i = 0; i < MAXCLIENTS; ++i)
        if (clients[i].used && clients[i].virt_ip == vip)
            return &clients[i];
    return NULL;
}

/* Allocate a new client slot */
static client_t *alloc_client(void)
{
    for (size_t i = 0; i < MAXCLIENTS; ++i)
    {
        if (!clients[i].used)
        {
            memset(&clients[i], 0, sizeof(client_t));
            clients[i].used = true;
            clients[i].id = (uint32_t)(i + 1u);
            clients[i].virt_ip = VPN_SUBNET_H | (0x00000002u + (uint32_t)i); /* 10.8.0.2+i */
            clients[i].send_ctr = 1u;
            return &clients[i];
        }
    }
    return NULL;
}

/* Replay protection for incoming packets */
static bool replay_ok(client_t *c, uint64_t ctr)
{
    if (ctr > c->recv_high)
    {
        uint64_t shift = ctr - c->recv_high;
        c->recv_window = (shift >= 64u) ? 1ull : ((c->recv_window << shift) | 1ull);
        c->recv_high = ctr;
        return true;
    }
    else
    {
        uint64_t diff = c->recv_high - ctr;
        if (diff >= 64u)
            return false;
        uint64_t mask = 1ull << diff;
        if (c->recv_window & mask)
            return false; /* seen */
        c->recv_window |= mask;
        return true;
    }
}

/* Global running flag for signal handler */
static volatile bool running = true;

static void handle_signal(int sig)
{
    (void)sig;
    running = false;
}

int main(void)
{
    int tun_fd = -1, udp_fd = -1;
    struct pollfd pfds[2];
    uint8_t inbuf[MAXPKT], outbuf[MAXPKT];
    const char *psk_path = getenv("AVPN_PSK_FILE");

    /* Signal handling */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

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
    memset(clients, 0, sizeof(clients));
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

    printf("[debug] Creating UDP server socket\n");
    udp_fd = udp_server_socket(NULL, (unsigned short)AVPN_PORT);
    if (udp_fd < 0)
    {
        fprintf(stderr, "[fatal] udp_server_socket failed\n");
        close(tun_fd);
        return 1;
    }
    printf("[debug] UDP server socket created successfully: fd=%d\n", udp_fd);

    pfds[0] = (struct pollfd){.fd = udp_fd, .events = POLLIN};
    pfds[1] = (struct pollfd){.fd = tun_fd, .events = POLLIN};

    printf("[debug] Starting VPN server loop\n");
    printf("[debug] UDP fd: %d, TUN fd: %d\n", udp_fd, tun_fd);
    fflush(stdout);
    
    while (running)
    {
        int poll_result = poll(pfds, 2, 1000); /* 1 sec timeout to check running */
        if (poll_result < 0)
        {
            if (!running) break; /* Interrupted by signal */
            perror("poll");
            break;
        }

        /* Handle incoming UDP packets */
        if (pfds[0].revents & POLLIN)
        {
            printf("[debug] Reading from UDP socket\n");
            fflush(stdout);
            struct sockaddr_in src;
            ssize_t r = udp_recvfrom(udp_fd, inbuf, sizeof(inbuf), &src);
            printf("[debug] udp_recvfrom returned: %zd\n", r);
            printf("[debug] UDP src: %s:%u\n", inet_ntoa(src.sin_addr), ntohs(src.sin_port));
            fflush(stdout);
            if (r > 0 && (size_t)r >= sizeof(avpn_hdr_t))
            {
                const avpn_hdr_t *h = (const avpn_hdr_t *)inbuf;
                if (ntohl(h->magic) == AVPN_MAGIC && h->ver == (uint8_t)AVPN_VER)
                {
                    if (h->type == (uint8_t)MSG_HELLO)
                    {
                        uint8_t plain[64];
                        size_t plen = 0;
                        uint32_t cid_ign = 0;
                        uint64_t ctr = 0;
                        if (avpn_open_encrypted(inbuf, (size_t)r, (uint8_t)MSG_HELLO,
                                                &cid_ign, psk, plain, &plen, &ctr) == 0)
                        {
                            printf("[debug] Handshake packet decrypted successfully.\n");
                            fflush(stdout);
                            client_t *c = alloc_client();
                            if (c)
                            {
                                assign_t asg = {.assigned_ip = htonl(c->virt_ip)};
                                size_t pkt = avpn_build_encrypted(outbuf, sizeof(outbuf), (uint8_t)MSG_ASSIGN,
                                                                  c->id, c->send_ctr++, psk,
                                                                  (const uint8_t *)&asg, sizeof(asg));
                                c->peer = src;
                                c->recv_high = 0;
                                c->recv_window = 0;
                                if (pkt == 0)
                                {
                                    fprintf(stderr, "[error] Failed to build ASSIGN packet\n");
                                }
                                else if (udp_sendto(udp_fd, outbuf, pkt, &src) < 0)
                                {
                                    fprintf(stderr, "[error] Failed to send ASSIGN packet\n");
                                }
                                else
                                {
                                    printf("[debug] ASSIGN packet sent to client %s:%u\n", inet_ntoa(src.sin_addr), ntohs(src.sin_port));
                                    fflush(stdout);
                                }
                            }
                        }
                        else
                        {
                            printf("[debug] Failed to decrypt handshake packet.\n");
                            fflush(stdout);
                        }
                    }
                    else if (h->type == (uint8_t)MSG_DATA)
                    {
                        uint8_t plain[MAXPKT];
                        size_t plen = 0;
                        uint32_t cid = 0;
                        uint64_t ctr = 0;
                        if (avpn_open_encrypted(inbuf, (size_t)r, (uint8_t)MSG_DATA,
                                                &cid, psk, plain, &plen, &ctr) == 0)
                        {
                            printf("[debug] Data packet decrypted successfully.\n");
                            fflush(stdout);
                            client_t *c = find_by_id(cid);
                            if (c && replay_ok(c, ctr))
                            {
                                if (tun_write(tun_fd, plain, plen) < 0)
                                {
                                    fprintf(stderr, "[error] Failed to write decrypted packet to TUN\n");
                                }
                                c->peer = src;
                            }
                        }
                        else
                        {
                            printf("[debug] Failed to decrypt data packet.\n");
                            fflush(stdout);
                        }
                    }
                }
                else
                {
                    printf("[debug] Received packet with invalid magic or version.\n");
                    fflush(stdout);
                }
            }
            else
            {
                printf("[debug] Received UDP packet too small for AVPN header.\n");
                fflush(stdout);
            }
        }

        /* Handle incoming TUN packets */
        if (pfds[1].revents & POLLIN)
        {
            printf("[debug] Reading from TUN interface\n");
            ssize_t r2 = tun_read(tun_fd, inbuf, sizeof(inbuf));
            if (r2 > 0 && (size_t)r2 >= 20)
            {
                uint32_t dst_net;
                memcpy(&dst_net, inbuf + 16, 4);
                uint32_t dst_host = ntohl(dst_net);
                client_t *dst = find_by_virt(dst_host);
                printf("[debug] Destination host: %u\n", dst_host);
                printf("[debug] Destination client: %p\n", (void *)dst);
                if (dst)
                {
                    size_t pkt = avpn_build_encrypted(outbuf, sizeof(outbuf), (uint8_t)MSG_DATA,
                                                      dst->id, dst->send_ctr++, psk,
                                                      inbuf, (size_t)r2);
                    printf("[debug] Sending encrypted packet to client %u (%zu bytes)\n", dst->id, pkt);
                    if (pkt == 0)
                    {
                        fprintf(stderr, "[error] Failed to build DATA packet\n");
                    }
                    else if (udp_sendto(udp_fd, outbuf, pkt, &dst->peer) < 0)
                    {
                        fprintf(stderr, "[error] Failed to send DATA packet to client\n");
                    }
                }
                else
                {
                    fprintf(stderr, "[error] No client found for destination %u\n", dst_host);
                }
            }
        }
    }

    printf("[info] Server shutting down\n");
    secure_memzero(psk, sizeof(psk));
    close(udp_fd);
    close(tun_fd);
    return 0;
}