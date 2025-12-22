
/*
 * util.c
 * Small utilities
 */

#include "util.h"
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

/*
 * Generate a 12-byte nonce from a 64-bit counter.
 */
void nonce_from_counter(uint64_t ctr, uint8_t out12[12])
{
    memset(out12, 0, 12);
    out12[4] = (uint8_t)((ctr >> 56) & 0xFFu);
    out12[5] = (uint8_t)((ctr >> 48) & 0xFFu);
    out12[6] = (uint8_t)((ctr >> 40) & 0xFFu);
    out12[7] = (uint8_t)((ctr >> 32) & 0xFFu);
    out12[8] = (uint8_t)((ctr >> 24) & 0xFFu);
    out12[9] = (uint8_t)((ctr >> 16) & 0xFFu);
    out12[10] = (uint8_t)((ctr >> 8) & 0xFFu);
    out12[11] = (uint8_t)(ctr & 0xFFu);
}

/*
 * Load a 32-byte PSK from file.
 * Returns true on success, false on error.
 */
bool load_psk(const char *path, uint8_t out_key[32])
{
    int fd;
    ssize_t r;
    if (!path)
        return false;
    fd = open(path, O_RDONLY);
    if (fd < 0)
    {
        perror("open psk");
        return false;
    }
    r = read(fd, out_key, 32);
    (void)close(fd);
    if (r != 32)
    {
        fprintf(stderr, "[psk] expected 32 bytes, got %ld\n", (long)r);
        return false;
    }
    return true;
}

/*
 * Securely zero memory (for keys, secrets).
 */
void secure_memzero(void *p, size_t n)
{
    volatile uint8_t *q = (volatile uint8_t *)p;
    while (n--)
    {
        *q++ = 0;
    }
}

/*
 * Set file descriptor to non-blocking mode.
 * Returns true on success, false on error.
 */
bool set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return false;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return false;
    return true;
}