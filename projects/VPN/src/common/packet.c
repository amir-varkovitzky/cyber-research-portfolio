
/*
 * packet.c
 * Build/open encrypted AVPN packets (C99)
 * NASA-style: clear, secure, robust.
 */

#include "packet.h"
#include "aead.h"
#include "proto.h"
#include "util.h"
#include <string.h>
#include <arpa/inet.h>

static void nonce_from_ctr(uint64_t ctr, uint8_t nonce[12]) { nonce_from_counter(ctr, nonce); }

/*
 * Build an encrypted AVPN packet.
 * Returns packet length on success, 0 on error.
 */
size_t avpn_build_encrypted(uint8_t *out, size_t out_cap,
                            uint8_t type, uint32_t client_id, uint64_t send_ctr,
                            const uint8_t *key32,
                            const uint8_t *plain, size_t plain_len)
{
    avpn_hdr_t h = {0};
    size_t c_len = 0;
    
    /* Sanity checks */
    if (!out || !key32 || (!plain && plain_len > 0))
        return 0u;

    if (plain_len > AVPN_MAX_PAYLOAD) /* Enforce max payload size */
        return 0u;

    /* Check if output buffer has enough space for Header + Ciphertext + Tag */
    if (out_cap < sizeof(h) + plain_len + AVPN_TAG_LEN)
        return 0u;

    h.magic = htonl(AVPN_MAGIC);
    h.ver = (uint8_t)AVPN_VER;
    h.type = type;
    h.rsv = 0u;
    h.client_id = htonl(client_id);
    nonce_from_ctr(send_ctr, h.nonce);
    
    memcpy(out, &h, sizeof(h));
    
    if (aead_seal(key32, h.nonce, (const uint8_t *)&h, sizeof(h),
                  plain, plain_len, out + sizeof(h), &c_len) != 0)
        return 0u;
        
    /* Double check resulting length */
    if (sizeof(h) + c_len > out_cap)
        return 0u;

    return sizeof(h) + c_len;
}

/*
 * Open and decrypt an AVPN packet.
 * Returns 0 on success, -1 on error.
 */
int avpn_open_encrypted(const uint8_t *in, size_t in_len,
                        uint8_t expected_type, uint32_t *client_id_out,
                        const uint8_t *key32,
                        uint8_t *plain_out, size_t *plain_len_out,
                        uint64_t *nonce_ctr_out)
{
    const avpn_hdr_t *h;
    size_t cipher_len;
    size_t plain_len = 0u;
    uint64_t ctr;
    
    if (!in || !key32 || !plain_out || !plain_len_out)
        return -1;

    if (in_len < sizeof(avpn_hdr_t) + AVPN_TAG_LEN) /* Minimal packet size */
        return -1;
        
    h = (const avpn_hdr_t *)in;
    if (ntohl(h->magic) != AVPN_MAGIC)
        return -1;
    if (h->ver != (uint8_t)AVPN_VER)
        return -1;
    if (expected_type && h->type != expected_type)
        return -1;
        
    cipher_len = in_len - sizeof(*h);
    
    if (aead_open(key32, h->nonce, (const uint8_t *)h, sizeof(*h),
                  in + sizeof(*h), cipher_len, plain_out, &plain_len) != 0)
        return -1;
        
    if (client_id_out)
        *client_id_out = ntohl(h->client_id);
    if (plain_len_out)
        *plain_len_out = plain_len;
    if (nonce_ctr_out)
    {
        ctr = ((uint64_t)h->nonce[4] << 56) |
              ((uint64_t)h->nonce[5] << 48) |
              ((uint64_t)h->nonce[6] << 40) |
              ((uint64_t)h->nonce[7] << 32) |
              ((uint64_t)h->nonce[8] << 24) |
              ((uint64_t)h->nonce[9] << 16) |
              ((uint64_t)h->nonce[10] << 8) |
              ((uint64_t)h->nonce[11]);
        *nonce_ctr_out = ctr;
    }
    return 0;
}