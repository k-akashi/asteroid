#define FALSE 0
#define TRUE 1

#define MAX_POOL 4096
#define MAX_BUF 2048

#define likely(x)      __builtin_expect(!!(x), 1)
#define unlikely(x)    __builtin_expect(!!(x), 0)

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ARG(a) a[0], a[1], a[2], a[3], a[4], a[5]

struct iflist {
    char devname[16];
    struct iflist *next;
};

struct pkt_pool {
    struct timeval * tv;
    uint32_t used;
};
