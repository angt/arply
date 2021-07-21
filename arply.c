#define _GNU_SOURCE

#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>

#include <linux/filter.h>
#include <linux/if_arp.h>

#define COUNT(x) (sizeof(x) / sizeof((x)[0]))

volatile sig_atomic_t arply_quit;

struct arply_addr {
    unsigned char ll[ETH_ALEN];
    unsigned char ip[4];
};

union arply_pkt {
    struct {
        struct ethhdr eth;
        struct arphdr arp;
        struct arply_addr s, t;
    } x;
    unsigned char buf[1UL << 16];
};

struct arply {
    int fd;
    unsigned index;
    unsigned char ll[ETH_ALEN];
};

static void
arply_sa_handler()
{
    arply_quit = 1;
}

static int
arply_init(struct arply *arply, char *name)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name) - 1);

    arply->fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (arply->fd == -1) {
        perror("socket");
        return 1;
    }
    if (ioctl(arply->fd, SIOCGIFINDEX, &ifr) || ifr.ifr_ifindex <= 0) {
        fprintf(stderr, "No interface %s found!\n", ifr.ifr_name);
        return 1;
    }
    arply->index = ifr.ifr_ifindex;

    if (ioctl(arply->fd, SIOCGIFHWADDR, &ifr)) {
        fprintf(stderr, "Unable to find the hwaddr of %s\n", ifr.ifr_name);
        return 1;
    }
    memcpy(&arply->ll, &ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    return 0;
}

static int
arply_listen(struct arply *arply)
{
    struct sockaddr_ll sll = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex = arply->index,
    };
    if (bind(arply->fd, (struct sockaddr *)&sll, sizeof(sll)) == -1) {
        perror("bind");
        return 1;
    }
    struct sock_filter filter[] = {
        {0x28, 0, 0,    0x0000000c},
        {0x15, 0, 3,    0x00000806},
        {0x28, 0, 0,    0x00000014},
        {0x15, 0, 1, ARPOP_REQUEST},
        {0x06, 0, 0,    0x00040000},
        {0x06, 0, 0,    0x00000000},
    };
    struct sock_fprog bpf = {
        .len = COUNT(filter),
        .filter = filter,
    };
    if (setsockopt(arply->fd, SOL_SOCKET, SO_ATTACH_FILTER,
                   &bpf, sizeof(bpf)) == -1) {
        perror("setsockopt(SO_ATTACH_FILTER)");
        return 1;
    }
    return 0;
}

static int
arply_recv(struct arply *arply, union arply_pkt *pkt)
{
    ssize_t r = recv(arply->fd, pkt, sizeof(*pkt), 0);

    if (r < (ssize_t)sizeof(pkt->x)) {
        if (r == (ssize_t)-1)
            perror("recv");
        return -1;
    }
    if ((pkt->x.arp.ar_op != htons(ARPOP_REQUEST)) ||
        (pkt->x.arp.ar_hln != sizeof(pkt->x.s.ll)) ||
        (pkt->x.arp.ar_pln != sizeof(pkt->x.s.ip)))
        return -1;

    return 0;
}

static void
arply_set_signal(void)
{
    struct sigaction sa = {
        .sa_flags = 0,
    };
    sigemptyset(&sa.sa_mask);

    sa.sa_handler = arply_sa_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    sa.sa_handler = SIG_IGN;
    sigaction(SIGALRM, &sa, NULL);
    sigaction(SIGPIPE, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
}

static uint32_t
ipmask(unsigned char a[4], uint32_t mask)
{
    uint32_t tmp;
    memcpy(&tmp, a, 4);
    return tmp & mask;
}

static const char *
uparse(const char *s, unsigned *ret, unsigned n)
{
    int i = 0;
    unsigned v = 0;

    for (i = 0; v <= n && s[i] >= '0' && s[i] <= '9'; i++)
        v = 10 * v + s[i] - '0';

    if (i && v <= n)
        *ret = v;

    return s + i;
}

static const char *
cparse(const char *s, char c)
{
    return s + (s[0] == c);
}

static const char *
ipparse(const char *s, uint32_t *ret)
{
    unsigned i0 = 256, i1 = 256, i2 = 256, i3 = 256;

    s = cparse(uparse(s, &i0, 255), '.');
    s = cparse(uparse(s, &i1, 255), '.');
    s = cparse(uparse(s, &i2, 255), '.');
    s = uparse(s, &i3, 255);

    if (i0 < 256 && i1 < 256 && i2 < 256 && i3 < 256)
        *ret = i3 << 24 | i2 << 16 | i1 << 8 | i0;

    return s;
}

int
main(int argc, char **argv)
{
    arply_set_signal();

    if (argc < 3 || argc > 4) {
        printf("usage: %s IFNAME { IP[/CIDR] | IP [MASK] }\n", argv[0]);
        return 1;
    }
    uint32_t ip = 0;
    unsigned cidr = 0;
    uint32_t mask = 0;
    struct arply arply;

    const char *s = ipparse(argv[2], &ip);
    int have_cidr = s[0] == '/';

    if (!ip || (s[0] && !have_cidr)) {
        fprintf(stderr, "Unable to parse ip %s\n", argv[2]);
        return 1;
    }
    if (have_cidr && (uparse(s + 1, &cidr, 32)[0] || !cidr)) {
        fprintf(stderr, "Unable to parse CIDR %s\n", s);
        return 1;
    }
    if (argc == 4) {
        if (have_cidr) {
            fprintf(stderr, "Mask, or CIDR, that is the question...\n");
            return 1;
        }
        if (ipparse(argv[3], &mask)[0] || !mask) {
            fprintf(stderr, "Unable to parse mask %s\n", argv[3]);
            return 1;
        }
    }
    if (!mask) {
        mask = UINT32_MAX;
        if (cidr > 0 && cidr < 32)
            mask = htonl(mask << (32 - cidr));
    }
    ip &= mask;

    if (arply_init(&arply, argv[1]))
        return 1;

    printf("Start replying ARP Request:\n"
           " src %02x:%02x:%02x:%02x:%02x:%02x\n",
           arply.ll[0], arply.ll[1],
           arply.ll[2], arply.ll[3],
           arply.ll[4], arply.ll[5]);

    if (arply_listen(&arply))
        return 1;

    union arply_pkt pkt;

    struct pollfd fd = {
        .fd = arply.fd,
        .events = POLLIN,
    };
    while (!arply_quit) {
        int p = poll(&fd, 1, -1);

        if (p <= 0) {
            if (p == -1 && errno != EINTR) {
                perror("poll");
                return 1;
            }
            continue;
        }
        if ((fd.revents & POLLIN) && !arply_recv(&arply, &pkt)) {
            if (ipmask(pkt.x.t.ip, mask) != ip)
                continue;

            unsigned char tmp[4];
            memcpy(&tmp, &pkt.x.t.ip, sizeof(tmp));
            memcpy(&pkt.x.t, &pkt.x.s, sizeof(pkt.x.t));
            memcpy(&pkt.x.s.ll, &arply.ll, sizeof(pkt.x.s.ll));
            memcpy(&pkt.x.s.ip, &tmp, sizeof(pkt.x.s.ip));
            memcpy(pkt.x.eth.h_dest, pkt.x.eth.h_source, sizeof(pkt.x.eth.h_dest));
            memcpy(pkt.x.eth.h_source, &arply.ll, sizeof(pkt.x.eth.h_source));
            pkt.x.arp.ar_op = htons(ARPOP_REPLY);

            if (send(arply.fd, &pkt.x, sizeof(pkt.x), 0) == -1) {
                switch (errno) {
                case EINTR:     /* FALLTHRU */
                case EAGAIN:    /* FALLTHRU */
                case ENETDOWN:
                    break;
                default:
                    perror("send");
                    return 1;
                }
            }
        }
    }
}
