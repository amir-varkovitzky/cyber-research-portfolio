
/*
 * tun.c
 * TUN helpers
 */

#include "tun.h"
#include "util.h"
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <linux/if.h>

/*
 * Open a TUN device by name.
 * Returns file descriptor on success, -1 on error.
 */
int tun_open(const char *ifname)
{
    int fd = open("/dev/net/tun", O_RDWR);
    struct ifreq ifr;
    if (fd < 0)
    {
        perror("open /dev/net/tun");
        return -1;
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = (short)(IFF_TUN | IFF_NO_PI);
    if (ifname && *ifname)
    {
        strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    }
    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0)
    {
        perror("ioctl TUNSETIFF");
        close(fd);
        return -1;
    }
    (void)set_nonblock(fd);
    return fd;
}

/*
 * Read from TUN device.
 */
ssize_t tun_read(int fd, void *buf, size_t len) { return read(fd, buf, len); }

/*
 * Write to TUN device.
 */
ssize_t tun_write(int fd, const void *buf, size_t len) { return write(fd, buf, len); }