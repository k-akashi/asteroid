#ifndef __ASTEROID_H__
#define __ASTEROID_H__

#define MAX_POOL 4096
#define MAX_BUF 2048

#define likely(x)      __builtin_expect(!!(x), 1)
#define unlikely(x)    __builtin_expect(!!(x), 0)

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ARG(a) a[0], a[1], a[2], a[3], a[4], a[5]

#define BIT(nr) (1UL << (nr))

#define AST_NETLINK     1
#define AST_CDEV        2

unsigned char bcast_addr[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
unsigned char mcast_addr[] = { 0x01, 0x00, 0x5e };
unsigned char span_addr[] =  { 0x01, 0x80, 0xc2 };

struct iflist {
    char devname[16];
    struct iflist *next;
};

struct pkt_pool {
    struct timeval * tv;
    uint32_t used;
};

struct modulation {
    int dsss_idx;
    int ofdm_idx;
};

struct asteroid_options {
    bool beacon;
    bool tslot_emu;
    bool local_ack;
};

struct asteroid_ctx {
    struct nl_sock *sock;
    struct nl_cb *cb;
    struct nl_cache *cache;
    struct genl_family *family;
    int family_id;

    int mode;

    char *conf_file;
    int ifnum;
    struct asteroid_options *opts;

    struct wlan_macaddr *indexer;
    int gnv_sock;
    char *pif;
    char *o_addr;
    uint16_t o_port;
    uint32_t vni;

    struct modulation modulation;
    char *logfile;
    FILE *logfd;
    int verbose;
    bool wem_mode;
    bool daemonize;
};

#endif // __ASTEROID_H__
