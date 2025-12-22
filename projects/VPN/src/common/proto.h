/*
 * proto.h - VPN Protocol Definitions
 *
 * Defines the wire format, constants, and packet structures for the VPN protocol.
 * The protocol uses a custom header followed by encrypted payload.
 *
 * Usage:
 *   1. Use AVPN_* constants for magic numbers and versioning.
 *   2. Use avpn_hdr_t for parsing incoming packet headers.
 */

#ifndef PROTO_H
#define PROTO_H

#include <stdint.h>

#define AVPN_MAGIC      (0x4156504EU)  /* "AVPN" */
#define AVPN_VER        (1u)
#define AVPN_NONCE_LEN  (12u)
#define AVPN_TAG_LEN    (16u)
#define AVPN_PORT       (51820u)

/* Message types */
#define MSG_HELLO      (1u)
#define MSG_ASSIGN     (2u)
#define MSG_DATA       (3u)
#define MSG_KEEPALIVE  (4u)

/* Packet Header Structure (Packed) */
#pragma pack(push,1)
typedef struct {
    uint32_t magic;      /* Protocol Magic (AVPN) - Network Order */
    uint8_t  ver;        /* Protocol Version */
    uint8_t  type;       /* Message Type (MSG_*) */
    uint16_t rsv;        /* Reserved (0) */
    uint32_t client_id;  /* Client Identifier - Network Order */
    uint8_t  nonce[AVPN_NONCE_LEN]; /* AES-GCM Nonce */
} avpn_hdr_t;
#pragma pack(pop)

/* Payload Structures */
#pragma pack(push,1)
typedef struct { uint32_t want_id; } hello_t;      /* HELLO payload */
typedef struct { uint32_t assigned_ip; } assign_t; /* ASSIGN payload */
#pragma pack(pop)

#endif /* PROTO_H */