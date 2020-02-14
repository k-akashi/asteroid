#include <iostream>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <pthread.h>
#include <sys/queue.h>
#include <sys/poll.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <getopt.h>
#include <string>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "asteroid.hpp"
#include "per.hpp"
#include "path_loss.hpp"
#include "geneve.hpp"
#include "config.hpp"
#include "hwsim.hpp"
#include "common.hpp"

#include "hwsim_mmap.h"

#define DEVICE_FILENAME "/dev/hwsim_cdev"

#define ERROR(fmt, ...) \
    printf("%s [%s: %d] Error: " fmt, \
    __FILE__, __func__, __LINE__, ##__VA_ARGS__)

struct iflist *in_ifhead = NULL;
struct iflist *in_iflist = NULL;
static int array_size = 0;

struct sockaddr_in daddr;
struct sockaddr_in laddr;

int tslot_emu  = FALSE;
pthread_mutex_t tslot_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t gnv_lock = PTHREAD_MUTEX_INITIALIZER;
int link_rate = 54;
int def_rate_idx = 11;
uint32_t offset_t = 0;
int beacon_rate = 1;

int mmap_fd;

//LIST_HEAD(listhead, mmap_mbuf) head = LIST_HEAD_INITIALIZER(head);
//struct listhead *headp;
//struct mbuf_list {
//    struct mmap_mbuf *mbuf;
//    LIST_ENTRY(mbuf_list) mbuf_lists;
//} *m1, *m2, *m3, *mp, *mp_temp;
//
//LIST_INIT(&head);

void
usage()
{
    fprintf(stderr, "Usage: asteroid -w <WLAN_IFNAME> -p <PHYSICAL_IFNAME> ");
    fprintf(stderr, "[-i VNI] [-l <LOGFILE> [-t -r <RATE> [-l <LATENCY>]] ");
    fprintf(stderr, "[-v] [-x] [-h]\n");
    fprintf(stderr, "    -c CONF_FILE           : wireless interface file\n");
    fprintf(stderr, "    -w WIRELESS_IFNAME     : wireless interface\n");
    fprintf(stderr, "    -p PHYSICAL_IFNAME     : ethernet interface\n");
    fprintf(stderr, "    -P DESTINATION_ADDRESS : Destination IP Address\n");
    fprintf(stderr, "    -i VNI                 : Geneve Virtual Network Identifier. default: 5001\n");
    fprintf(stderr, "    -r RATE[Mbps]          : emulation link speed. required -t.\n");
    fprintf(stderr, "                                RATE: 6 9 12 18 24 36 48 54\n");
    fprintf(stderr, "    -l LATENCY[us]         : offset transmission time. latency between servers.\n");
    fprintf(stderr, "    -v                     : verbose mode\n");
    fprintf(stderr, "    -f                     : log file name\n");
    fprintf(stderr, "    -h                     : help\n");
}

static void
pktdump(uint8_t* buf, int len)
{
/*
    if (verbose >= 3) {
        return;
    }
    static pthread_mutex_t lock_memdump = NULL;
    if (lock_memdump == NULL) {
        pthread_mutex_init(&lock_memdump, NULL);

    }
    pthread_mutex_lock(&lock_memdump);
*/

    #define P(x) ((c >= ' ' && c < 0x7f) ? c : '.')
    int i;
    char t[128];
    char hex[] = "0123456789abcdef";
    fprintf(stderr, "        --- %d bytes at %p\n", len, buf);
    if (len > 160) { 
        len = 160;
    }       
    for (i = 0; i < len; i++) {
        uint8_t c = (uint8_t)buf[i];
        int o = i % 16;
        if (o == 0) {
            if (i > 0) {
                fprintf(stderr, "        %s\n", t);
            }
            memset(t, ' ', 79);
            t[80] = '\0';
            t[0] = hex[(i>>12) & 0xf];
            t[1] = hex[(i>>8) & 0xf];
            t[2] = hex[(i>>4) & 0xf];
            t[3] = hex[(i>>0) & 0xf];
            t[4] = ':';
        }
        t[6 + 3*o + (o >> 3)] = hex[c >> 4];
        t[7 + 3*o + (o >> 3)] = hex[c & 0xf];
        t[56 + o + (o >> 3)] = P(c);
    }
    if (len) {
        fprintf(stderr, "        %s\n", t);
    }   
    return;
}    

inline void cas_lock(uint8_t *lock)
{
    while (__sync_lock_test_and_set(lock, 1)) { };
    return;
}

inline void cas_unlock(uint8_t *lock)
{
    __sync_lock_release(lock);
    return;
}

inline void
print_frame_info(struct asteroid_ctx *ctx, struct hwsim_frame *frame)
{
    fprintf(ctx->logfd, "    frame info:\n");
    fprintf(ctx->logfd, "        phy addr: " MAC_FMT "\n", MAC_ARG(frame->phyaddr));
    fprintf(ctx->logfd, "        flags: %d\n", frame->flags);
    fprintf(ctx->logfd, "        signal: %d\n", frame->signal);
    fprintf(ctx->logfd, "        cookie: %lu\n", frame->cookie);
}

void
print_wlan_macaddr(struct asteroid_ctx *ctx, struct wlan_macaddr *addr, int cr)
{
    fprintf(ctx->logfd, "\t%02x:%02x:%02x:%02x:%02x:%02x", 
            addr->addr[0], addr->addr[1], addr->addr[2],
            addr->addr[3], addr->addr[4], addr->addr[5]);
    if (cr) {
        fprintf(ctx->logfd, "\n");
    }
    fflush(ctx->logfd);
}

void
dump_macaddress(struct asteroid_ctx *ctx, int ifnum)
{
    int i;
    void *ptr = ctx->indexer;
    struct wlan_macaddr *addr;
    for (i = 0; i < ifnum; i++) {
        addr = (struct wlan_macaddr *)ptr;
        fprintf(ctx->logfd, MAC_FMT "\n", MAC_ARG(addr->addr));
        ptr = (char *)ptr + sizeof (struct wlan_macaddr);
    }
}

void
put_wlan_macaddr(struct asteroid_ctx *ctx, struct wlan_macaddr addr, int pos)
{   
    int i;
    void *ptr = ctx->indexer;
    
    for (i = 0; i < pos ; i++) {
        ptr = (char *)ptr + sizeof (struct wlan_macaddr);
    }
    memcpy(ptr, &addr, sizeof (struct wlan_macaddr));
}  

int
init_probability(struct asteroid_ctx *ctx)
{
    ctx->indexer = MALLOC(struct wlan_macaddr, 256);

    if (ctx->indexer == NULL) {
        fprintf(ctx->logfd, "Problem allocating vector");
        fflush(ctx->logfd);
        exit(1);
    }

    return 0;
}

int
parse_conf(struct asteroid_ctx *ctx)
{
    int i;
    int ifnum = 0;
    struct wlan_macaddr addr;
    struct node_data *nlist;

    memset(&addr, 0, sizeof (struct wlan_macaddr));

    ctx->ifnum = get_node_cnt(ctx->conf_file);
    nlist = create_node_list(ctx->conf_file, ifnum);
    dump_node_list(nlist, ifnum);

    init_probability(ctx);
    void *ptr = ctx->indexer;
    char *oct;
    int oct_ptr;
    for (i = 0; i < ifnum ; i++) {
        oct = strtok(nlist->mac, ":");
        addr.addr[0] = (atoi(oct) / 10) * 16 + (atoi(oct) % 10);
        for (oct_ptr = 1; oct_ptr <= 5; oct_ptr++) {
            oct = strtok(NULL, ":");
            addr.addr[oct_ptr] = strtol(oct, NULL, 16);
        }
        memcpy(ptr, &addr, sizeof (struct wlan_macaddr));
        ptr = (char *)ptr + sizeof (struct wlan_macaddr);
        nlist++;
    }

    return 0;
}

int
rate2signal(int idx)
{
    const int r2s[] = { -80,-77,-74,-71,-69,-66,-64,-62,-59,-56,-53,-50 };
    if (idx >= 0 || idx < IEEE80211_AVAILABLE_RATES) {
        return r2s[idx];
    }
    else {
        return 0;
    }
}

struct wlan_macaddr *
get_wlan_macaddr(struct asteroid_ctx *ctx, int pos) {

    void * ptr = ctx->indexer;
    ptr = (char *)ptr + (sizeof (struct wlan_macaddr) * pos);

    if (pos >= array_size) {
        return NULL;
    }
    else {
        return (struct wlan_macaddr *)ptr;
    }
}

struct wlan_macaddr
string_to_wlan_macaddr(const char* str)
{   
    struct wlan_macaddr mac; 
    int a[6];
        
    sscanf(str, "%x:%x:%x:%x:%x:%x", &a[0], &a[1], &a[2], &a[3], &a[4], &a[5]);

    mac.addr[0] = a[0];
    mac.addr[1] = a[1];
    mac.addr[2] = a[2];
    mac.addr[3] = a[3];
    mac.addr[4] = a[4];
    mac.addr[5] = a[5];

    printf(MAC_FMT, MAC_ARG(mac.addr));

    return mac;
} 

uint8_t *gnv_ = gnv_alloc();

int
send_lan(struct asteroid_ctx *ctx, struct hwsim_frame *frame)
{
    int pkt_len;
    int rate_size;
    uint8_t type = 0;
    struct packed_data pdata;
    uint8_t *gnv = gnv_;

    add_gnv_hdr(gnv, ctx->vni, GNV_WL_BRIDGE);

    pdata.type = TX;
    memcpy(pdata.wlan_src_addr, frame->wlan_src_addr, ETH_ALEN);
    memcpy(pdata.wlan_dst_addr, frame->wlan_dst_addr, ETH_ALEN);
    memcpy(pdata.phyaddr, frame->phyaddr, ETH_ALEN);
    pdata.flags = frame->flags;
    pdata.tx_rate_cnt = frame->tx_rate_cnt;
    rate_size = frame->tx_rate_cnt * sizeof (struct hwsim_tx_rate);
    memcpy(&(pdata.tx_rates), frame->tx_rates, rate_size);
    pdata.tx_rates[0].idx = def_rate_idx;

    pdata.signal = frame->signal;
    pdata.cookie = frame->cookie;
    pdata.seq = frame->seq;

    // put frame info
    pkt_len = add_gnv_opt(gnv, type, sizeof (struct packed_data), (uint8_t *)&pdata);
    if (pkt_len == -1) {
        fprintf(ctx->logfd, "cannot add option header\n");
        fflush(ctx->logfd);

        return -1;
    }

    // put frame type
    pkt_len = add_gnv_opt(gnv, 1, 4, frame->data);
    if (pkt_len == -1) {
        fprintf(ctx->logfd, "cannot add option header\n");
        fflush(ctx->logfd);

        return -1;
    }

    pkt_len = add_gnv_payload(gnv, frame->data + 4, frame->data_len - 4);
    if (pkt_len == -1) {
        fprintf(ctx->logfd, "cannot add original frame\n");
        fflush(ctx->logfd);

        return -1;
    }

    if (ctx->verbose >= 1) {
        fprintf(ctx->logfd, "--> Send geneve pkt src: " MAC_FMT " dst: " MAC_FMT "\n", 
                MAC_ARG(frame->wlan_src_addr),
                MAC_ARG(frame->wlan_dst_addr));
    }

    if (sendto(ctx->gnv_sock, (void *)gnv, pkt_len, 0, (struct sockaddr *)&daddr, sizeof (daddr)) < 0) {
        perror("sendto");

        return -1;
    }

    return 0;
}

int
send_wlan(struct asteroid_ctx *ctx, struct hwsim_frame *frame)
{
    int rc, i;
    struct wlan_macaddr *dst;
    struct nl_msg *nlmsg;

    frame->tx_rates->idx = def_rate_idx;

    for (i = 0; i < ctx->ifnum; i++) {
        nlmsg = nlmsg_alloc();
        if (!nlmsg) {
            fprintf(ctx->logfd, "Error allocating new message MSG!\n"); 
            fflush(ctx->logfd);
            nlmsg_free(nlmsg);
            return -1;
        }

        dst = get_wlan_macaddr(ctx, i);
        if (!dst) {
            fprintf(ctx->logfd, "[%s] dst[%d]: %p\n", __func__, i, dst);
            dst = &phy_addr_default;
            //continue;
        }
        if (memcmp(frame->wlan_src_addr, dst->addr, ETH_ALEN) == 0) {
            fprintf(ctx->logfd, "Error src_addr == dst_addr: " 
                    MAC_FMT " == " MAC_FMT "\n", 
                    MAC_ARG(frame->wlan_src_addr),
                    MAC_ARG(frame->wlan_dst_addr));
            nlmsg_free(nlmsg);
            continue;
        }

        genlmsg_put(nlmsg, NL_AUTO_PID, NL_AUTO_SEQ, ctx->family_id, 
                0, NLM_F_REQUEST, HWSIM_CMD_FRAME, VERSION_NR);
        if (nla_put(nlmsg, HWSIM_ATTR_ADDR_RECEIVER, ETH_ALEN, dst->addr) != 0) {
            fprintf(ctx->logfd, "Error[%s]: HWSIM_ATTR_ADDR_RECEIVER\n", __func__);
            fflush(ctx->logfd);
            nlmsg_free(nlmsg);
            continue;
        }
        if (nla_put(nlmsg, HWSIM_ATTR_FRAME, frame->data_len, frame->data) != 0) {
            fprintf(ctx->logfd, "Error[%s]: HWSIM_ATTR_FRAME\n", __func__);
            fflush(ctx->logfd);
            nlmsg_free(nlmsg);
            continue;
        }
        //if (nla_put_u32(nlmsg, HWSIM_ATTR_RX_RATE, frame->tx_rates->idx) != 0) {
        if (nla_put_u32(nlmsg, HWSIM_ATTR_RX_RATE, 1) != 0) {
            fprintf(ctx->logfd, "Error[%s]: HWSIM_ATTR_RX_RATE\n", __func__);
            fflush(ctx->logfd);
            nlmsg_free(nlmsg);
            continue;
        }
        //if (nla_put_u32(nlmsg, HWSIM_ATTR_SIGNAL, frame->signal) != 0) {
        if (nla_put_u32(nlmsg, HWSIM_ATTR_SIGNAL, -50) != 0) {
            fprintf(ctx->logfd, "Error[%s]: HWSIM_ATTR_SIGNAL\n", __func__);
            fflush(ctx->logfd);
            nlmsg_free(nlmsg);
            continue;
        }

        if (ctx->verbose >= 1) {
            fprintf(ctx->logfd, "--> Send local      phy: " MAC_FMT "\n", 
                    MAC_ARG(dst->addr));
            if (ctx->verbose >= 2) {
                print_frame_info(ctx, frame);
            }
            if (ctx->verbose >= 3) {
                pktdump(frame->data, frame->data_len);
            }
        }
        rc = nl_send_auto_complete(ctx->sock, nlmsg);
        if (rc < 0) {
            fprintf(ctx->logfd, "Error[%s]: nl_send_auto_complete: %s\n",
                    __func__, nl_geterror(rc));
        }
        nlmsg_free(nlmsg);
    }

    return 0;
}
 
int
send_tx_ack(struct asteroid_ctx *ctx, struct hwsim_frame *frame)
{
    int rc;
    struct nl_msg *nlmsg;
    
    nlmsg = nlmsg_alloc();
    genlmsg_put(nlmsg, NL_AUTO_PID, NL_AUTO_SEQ, ctx->family_id,
            0, NLM_F_REQUEST, HWSIM_CMD_TX_INFO_FRAME, VERSION_NR);
    
    rc = nla_put(nlmsg, HWSIM_ATTR_ADDR_TRANSMITTER, ETH_ALEN, frame->phyaddr);
    if (rc != 0) {
        fprintf(ctx->logfd, "Error[%s]: HWSIM_ATTR_ADDR_TRANSMITTER: %s(%d)\n",
                __func__, nl_geterror(rc), rc);
        nlmsg_free(nlmsg);
        return -1;
    }
    rc = nla_put_u32(nlmsg, HWSIM_ATTR_FLAGS, frame->flags);
    if (rc != 0) {
        fprintf(ctx->logfd, "Error[%s]: HWSIM_ATTR_FLAGS: %s(%d)\n",
                __func__, nl_geterror(rc), rc);
        nlmsg_free(nlmsg);
        return -1;
    }
    rc = nla_put_u32(nlmsg, HWSIM_ATTR_SIGNAL, frame->signal);
    if (rc != 0) {
        fprintf(ctx->logfd, "Error[%s]: HWSIM_ATTR_SIGNAL: %s(%d)\n",
                __func__, nl_geterror(rc), rc);
        nlmsg_free(nlmsg);
        return -1;
    }
    rc = nla_put(nlmsg, HWSIM_ATTR_TX_INFO,
            frame->tx_rate_cnt * HWSIM_TX_RATE_SZ, frame->tx_rates);
    if (rc != 0) {
        fprintf(ctx->logfd, "Error[%s]: HWSIM_ATTR_TX_INFO: %s(%d)\n",
                __func__, nl_geterror(rc), rc);
        nlmsg_free(nlmsg);
        return -1;
    }
    rc = nla_put_u64(nlmsg, HWSIM_ATTR_COOKIE, frame->cookie);
    if (rc != 0) {
        fprintf(ctx->logfd, "Error[%s]: HWSIM_ATTR_COOKIE: %s(%d)\n",
                __func__, nl_geterror(rc), rc);
        nlmsg_free(nlmsg);
        return -1;
    }

    if (ctx->verbose >= 1) {
        fprintf(ctx->logfd, "----> Send tx ack   phy: " MAC_FMT "\n",
                MAC_ARG(frame->phyaddr));
        fflush(ctx->logfd);
        if (ctx->verbose >= 2) {
            print_frame_info(ctx, frame);
        }
    }

    rc = nl_send_auto_complete(ctx->sock, nlmsg);
    if (rc < 0) {
        fprintf(ctx->logfd, "Error[%s]: %s(%d)\n", 
                __func__, nl_geterror(rc), rc);
    }
    nlmsg_free(nlmsg);

    return 0;
}

int ofdm_simbol_lengh_11a[] = {
    24,     //  6 Mbps
    36,     //  9 Mbps
    48,     // 12 Mbps
    72,     // 18 Mbps
    96,     // 24 Mbps
    144,    // 36 Mbps
    192,    // 48 Mbps
    216     // 54 Mbps
};

#define PLCP_HDR_SRV 16
#define TAIL_BIT 6

int
rate2ofdm_idx(int rate) {
    switch(rate) {
        case 6:
            return 0;
            break;
        case 9:
            return 1;
            break;
        case 12:
            return 2;
            break;
        case 18:
            return 3;
            break;
        case 24:
            return 4;
            break;
        case 36:
            return 5;
            break;
        case 48:
            return 6;
            break;
        case 54:
            return 7;
            break;
        default:
            return -1;
            break;
    }
}

int
rate2dsss_idx(int rate) {
    switch(rate) {
        case 1:
            return 0;
            break;
        case 2:
            return 1;
            break;
        case 5:
            return 2;
            break;
        case 11:
            return 3;
            break;
        default:
            return -1;
            break;
    }
}

uint32_t
calc_transmission_time_11ag(uint32_t len, int rate)
{
    int idx;
    uint32_t msdu = 0;
    uint32_t delay_t = 0;
    uint32_t ceiling;

    idx = rate2ofdm_idx(rate);
    if (idx != -1) {
        msdu = 8 * len;
        ceiling = ((16 + 6 + (8 * L_H_DATA) + msdu) / ofdm_simbol_lengh_11a[idx]);
        delay_t = T_P_11A + T_PHY_11A + (4 * ceiling);
    }
    else if ((idx = rate2dsss_idx(rate)) != -1) {
        msdu = 8 * len;
        delay_t = 192 + (8 * ((34 + len) / rate));
    }

    // 1gbps transmission time 8ns
    delay_t = delay_t - (len * 8 * 8 / 1000);
    // offset time
    delay_t = delay_t - offset_t;

    // us -> ns
    delay_t = delay_t * 1000;
    if (delay_t <= 0) {
        delay_t = 0;
    }

    return delay_t;
}

uint32_t
calc_transmission_time_11b(uint32_t len, int rate)
{
    uint32_t delay_t;

    delay_t = T_P_11A + T_PHY_11A + (((8 * L_H_DATA) + (8 * len)) / (100000 * rate));
    delay_t *= 1000; // us -> ns

    // 1gbps transmission time 8ns
    delay_t -= len * 8 * 8;
    // offset time
    delay_t -= offset_t;

    return delay_t;
}

void
wait_sendtime(uint32_t len, int rate, int phy_mode)
{
    // 1Mbps link speed. 1byte send. 7629.39453125ns
    struct timespec stime = {0, 0};

    // PLCP Preamble PLCP header
    //double stime_1mbps = 7629.39453125;
    //stime.tv_nsec = plcp_tb[phy_mode];
    //stime.tv_nsec += ((stime_1mbps / rate) - (stime_1mbps / 1000))  * len;
    //stime.tv_nsec = stime.tv_nsec / 1000;

    /* oreore time calc
    int data_len;
    data_len = PLCP_HDR_SRV + ((MAC_HDR_LEN + MAC_LLC_LEN + len + MAC_FCS_LEN) * 8) + TAIL_BIT;
    data_len = data_len / ofdm_simbol_lengh_11a[ofdm_idx];
    stime.tv_nsec = (PLCP_PREAMBLE_11A + (4 * data_len)) * 1000; // us -> ns

    fprintf(ctx->logfd, "wait time: %lu\n", stime.tv_nsec);
    fflush(ctx->logfd);
    */

    if (phy_mode == PLCP_11A) {
        stime.tv_nsec = calc_transmission_time_11ag(len, rate);
    }
    else if (phy_mode == PLCP_11B) {
        stime.tv_nsec = calc_transmission_time_11b(len, rate);
    }
    nanosleep(&stime, NULL);
}
 
static int
wlan_frame_cb(struct nl_msg *nlmsg, void *arg)
{
    uint8_t *wlan_src_addr, *wlan_dst_addr, *phyaddr;
    struct nlattr *attrs[HWSIM_ATTR_MAX + 1];
    struct nlmsghdr *nlh = nlmsg_hdr(nlmsg);
    struct genlmsghdr *gnlh = (struct genlmsghdr *)nlmsg_data(nlh);
    struct asteroid_ctx *ctx = (struct asteroid_ctx *)arg;
    struct hwsim_frame *frame;
    struct hwsim_tx_rate *tx_rates;
    struct ieee80211_hdr *wlan_hdr;

    if(gnlh->cmd == HWSIM_CMD_FRAME) {
        genlmsg_parse(nlh, 0, attrs, HWSIM_ATTR_MAX, NULL);
        if (attrs[HWSIM_ATTR_ADDR_TRANSMITTER]) {
            phyaddr = (uint8_t *)nla_data(attrs[HWSIM_ATTR_ADDR_TRANSMITTER]);
            uint32_t data_len = nla_len(attrs[HWSIM_ATTR_FRAME]);
            uint8_t *data = (uint8_t *)nla_data(attrs[HWSIM_ATTR_FRAME]);

            uint32_t flags = nla_get_u32(attrs[HWSIM_ATTR_FLAGS]);

            uint32_t tx_rate_len = nla_len(attrs[HWSIM_ATTR_TX_INFO]);
            tx_rates = (struct hwsim_tx_rate *)nla_data(attrs[HWSIM_ATTR_TX_INFO]);
            uint64_t cookie = nla_get_u64(attrs[HWSIM_ATTR_COOKIE]);
            uint32_t freq = attrs[HWSIM_ATTR_FREQ] ? nla_get_u32(attrs[HWSIM_ATTR_FREQ]) : 2412;

            wlan_hdr = (struct ieee80211_hdr *)data;
            wlan_dst_addr = wlan_hdr->addr1;
            wlan_src_addr = wlan_hdr->addr2;

            if (data_len < 16) return -1;

            frame = (struct hwsim_frame *)malloc(sizeof (struct hwsim_frame) + data_len);

            memcpy(frame->data, data, data_len);
            frame->data_len = data_len;
            frame->flags = flags;
            frame->cookie = cookie;
            frame->freq = freq;
            memcpy(frame->phyaddr, phyaddr, ETH_ALEN);
            memcpy(frame->wlan_src_addr, wlan_src_addr, ETH_ALEN);
            memcpy(frame->wlan_dst_addr, wlan_dst_addr, ETH_ALEN);
            frame->tx_rate_cnt = tx_rate_len / sizeof(struct hwsim_tx_rate);
            memcpy(frame->tx_rates, tx_rates, tx_rate_len);
            frame->seq = 0;

            uint8_t *frame_type;
            frame_type = (uint8_t *)frame->data;

            if (ctx->verbose >= 1) {
                fprintf(ctx->logfd, "Recv from hwsim     src: " MAC_FMT "\n", 
                        MAC_ARG(frame->wlan_src_addr));
                if (ctx->verbose >= 3) {
                    pktdump(frame->data, frame->data_len);
                }
            }

/*
            int round;
            struct hwsim_tx_rate tx_rate;
            for (round = 0; round < IEEE80211_MAX_RATES_PER_TX; round++) {
                if (tx_rates[round].idx == -1) {
                    break;
                }
            }
            round--;
            tx_rate.idx   = tx_rates[round].idx;
            tx_rate.count = tx_rates[round].count;
*/
            frame->tx_rates->idx = def_rate_idx;

            if (tslot_emu) {
                int rate = link_rate;
                if (ctx->opts->beacon == true && (*frame_type & 0x0f) == 8) {
                    rate = beacon_rate;
                }

                //cas_lock(&tslot_lock);
                pthread_mutex_lock(&tslot_lock);
                wait_sendtime(frame->data_len, rate, PLCP_11A);
                pthread_mutex_unlock(&tslot_lock);
                //cas_unlock(&tslot_lock);
            }

            if (ctx->pif) {
                /*
                int i;
                struct timeval *tv;
                for (i = 0; i >= MAX_POOL; i++) {
                    if (ppool[i].used == true) {
                        continue;
                    }
                    gettimeofday(tv, NULL);
                    ppool[i].used = true;
                    ppool[i].tv = tv;
                    break;
                }
                */
                send_lan(ctx, frame);
            }
            //wlan2wlan(nlmsg, wlan_src_addr, data, len, flags, tx_rate, cookie);

            if (ctx->opts->local_ack == true) { // || frame->flags & HWSIM_TX_CTL_NO_ACK) {
                frame->flags |= HWSIM_TX_STAT_ACK;
                send_tx_ack(ctx, frame);
            }
        }
    }

    // IEEE 802.11a
    //   slot time: 9us
    //   SIFS time: 16us
    //   DIFS time: 34us
    //   minimam contention window: 15
    // backoff time average
    //   backoff_t = slot_time * (min_contention_window / 2) = 67.5us
    if (tslot_emu) {
        struct timespec backoff_t;
        backoff_t.tv_sec = 0;
        backoff_t.tv_nsec = 67500;
        nanosleep(&backoff_t, NULL);
    }

    return 0;
}

// Register to hwsim
int
send_register_msg(struct asteroid_ctx *ctx)
{
    struct nl_msg *nlmsg;
    nlmsg = nlmsg_alloc();
    if (!nlmsg) {
        return -1;
    }

    genlmsg_put(nlmsg, NL_AUTO_PID, NL_AUTO_SEQ, ctx->family_id, 0, NLM_F_REQUEST, 1, 1);
    nl_send_auto_complete(ctx->sock, nlmsg);
    nlmsg_free(nlmsg);

    return 0;
}

void
init_nl(struct asteroid_ctx *ctx)
{
    ctx->cb = nl_cb_alloc(NL_CB_CUSTOM);
    if (!ctx->cb) {
        printf("cannot alloc cb\n");
        exit(EXIT_FAILURE);
    }

    ctx->sock = nl_socket_alloc_cb(ctx->cb);
    if (!ctx->sock) {
        printf("cannot alloc socket\n");
        exit(EXIT_FAILURE);
    }

    nl_socket_set_nonblocking(ctx->sock);
    genl_connect(ctx->sock);
    genl_ctrl_alloc_cache(ctx->sock, &(ctx->cache));

    ctx->family = genl_ctrl_search_by_name(ctx->cache, "MAC80211_HWSIM");
    if (!ctx->family) {
        printf("cannot search family\n");
        exit(EXIT_FAILURE);
    }
    ctx->family_id = genl_family_get_id(ctx->family);

    nl_cb_set(ctx->cb, NL_CB_MSG_IN, NL_CB_CUSTOM, wlan_frame_cb, (void *)ctx);
}

int
init_wlan2lan(struct asteroid_ctx *ctx)
{
    int bcast = 0;
    int ifr_sock;
    uint32_t if_namelen;
    struct ifreq ifr;

    fprintf(ctx->logfd, "outgoing interface: %s\n", ctx->pif);
    fflush(ctx->logfd);
    ifr_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (ifr_sock == -1) {
        perror("socket");
        exit(1);
    }
    if_namelen = strlen(ctx->pif);
    if (if_namelen < sizeof(ifr.ifr_name)) {
        memcpy(ifr.ifr_name, ctx->pif, if_namelen);
        ifr.ifr_name[if_namelen] = 0;
    }
    if (ioctl(ifr_sock, SIOCGIFADDR, &ifr) == -1) {
        perror("ioctl");
        close(ifr_sock);
        exit(1);
    }
    laddr.sin_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;

    if (!ctx->o_addr) {
		if (ioctl(ifr_sock, SIOCGIFBRDADDR, &ifr) < 0) {
    	    perror("ioctl");
    	    close(ifr_sock);
    	    exit(1);
		}
        bcast = 1;
        ctx->o_addr = (char *)malloc(INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &((struct sockaddr_in *)(&ifr.ifr_broadaddr))->sin_addr, ctx->o_addr, INET_ADDRSTRLEN);
	}
    fprintf(ctx->logfd, "destination: %s\n", ctx->o_addr);

    ctx->gnv_sock = socket(AF_INET, SOCK_DGRAM, 0);
    daddr.sin_family = AF_INET;
    daddr.sin_port = htons(GNV_PORT);
    daddr.sin_addr.s_addr = inet_addr(ctx->o_addr);

    if (bcast == 1) {
        if (setsockopt(ctx->gnv_sock, SOL_SOCKET, SO_BROADCAST, &bcast, sizeof (bcast)) < 0) {
            perror("setsockopt");
            return -1;
        }
    }

    return 0;
}

struct mmap_mbuf *mbuf_ = (struct mmap_mbuf *)malloc(sizeof (struct mmap_mbuf));

int
hwsim_mmap_send2wlan(struct asteroid_ctx *ctx, struct hwsim_frame *frame)
{
    struct mmap_mbuf *mbuf = mbuf_;

    memcpy(mbuf->hdr.transmitter, frame->phyaddr, ETH_ALEN);
    mbuf->hdr.flags  = frame->flags;
    //mbuf->hdr.signal = frame->signal;
    mbuf->hdr.freq   = frame->freq;
	mbuf->hdr.cookie = frame->cookie;
    memcpy(mbuf->hdr.tx_attempts, frame->tx_rates, sizeof (struct hwsim_tx_rate) * IEEE80211_TX_MAX_RATES);

    mbuf->len = frame->data_len;
    memcpy(mbuf->data, frame->data, frame->data_len);

    write(mmap_fd, mbuf, PAGE_SIZE);

    return 0;
}

void *recv_buf = malloc(MAX_BUF);
struct hwsim_frame *recv_frame = (struct hwsim_frame *)malloc(MAX_BUF);
void *
recv_from_lan(void *param)
{
    void *buf = recv_buf;
    int recv_sock;
    int recv_len;
    int data_len;
    struct sockaddr_in addr;
    struct sockaddr_in from;
    struct asteroid_ctx *ctx = (struct asteroid_ctx *)param;
    socklen_t addr_len = sizeof(struct sockaddr_in);

    fprintf(ctx->logfd, "[%s] PID: %ld\n", __func__, syscall(SYS_gettid));
    recv_sock = socket(AF_INET, SOCK_DGRAM, 0);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(GNV_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(recv_sock, (struct sockaddr *)&addr, sizeof (addr));
    memset(buf, 0, MAX_BUF);

    //unsigned char bcast_addr[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    //unsigned char mcast_addr[] = { 0x01, 0x00, 0x5e };
    //unsigned char span_addr[] =  { 0x01, 0x80, 0xc2 };
    fprintf(ctx->logfd, "[%s] wait geneve packet\n", __func__);

    for (;;) {
        //recv_len = recv(recv_sock, buf, MAX_BUF, 0);
        recv_len = recvfrom(recv_sock, buf, MAX_BUF, 0, (struct sockaddr *)&from, &addr_len);
        if (ctx->verbose >= 1) {
            fprintf(ctx->logfd, "[%s] Receive Packet: %d\n", __func__, recv_len);
        }
        if (recv_len == 0) {
            fprintf(ctx->logfd, "[%s] receive length 0.\n", __func__);
            continue;
        }
        // 16777343 = 127.0.0.1;
        if ((from.sin_addr.s_addr == 16777343) || (laddr.sin_addr.s_addr == from.sin_addr.s_addr)) {
            continue;
        }

        // Geneve like pakcet.
        struct geneve_header *gnv_hdr = (struct geneve_header *)buf;
        if (ctx->vni != get_gnv_vni(gnv_hdr)) {
            // Drop different VNI frame;
            if (ctx->verbose >= 1) {
                fprintf(ctx->logfd, "[%s] Different VNI\n", __func__);
            }
            continue;
        }
        if (ntohs(gnv_hdr->proto_type) != GNV_WL_BRIDGE) {
            // Drop different proto type;
            if (ctx->verbose >= 1) {
                fprintf(ctx->logfd, "[%s] Invalid protocol type\n", __func__);
            }
            continue;
        }

        struct geneve_option *gnv_opt;
        gnv_opt = get_gnv_opt((uint8_t *)buf);
        struct packed_data *pdata = (struct packed_data *)(gnv_opt + 1);

        struct hwsim_frame *frame = recv_frame;
        data_len = recv_len - GNV_HDRLEN - (gnv_hdr->opt_len * 4) + 4;
        frame->data_len = recv_len - GNV_HDRLEN - (gnv_hdr->opt_len * 4) + 4;
        uint8_t *data = (uint8_t *)buf + GNV_HDRLEN + (gnv_hdr->opt_len * 4) - 4;
        memcpy(frame->data, data, frame->data_len);

        frame->flags = pdata->flags;
        memcpy(frame->wlan_dst_addr, pdata->wlan_dst_addr, ETH_ALEN);
        memcpy(frame->wlan_src_addr, pdata->wlan_src_addr, ETH_ALEN);
        memcpy(frame->phyaddr, pdata->phyaddr, ETH_ALEN);
        
        frame->cookie = pdata->cookie;
        frame->seq = pdata->seq;

        frame->tx_rate_cnt = pdata->tx_rate_cnt;
        memcpy((void *)frame->tx_rates, (void *)pdata->tx_rates, 
                frame->tx_rate_cnt * sizeof (struct hwsim_tx_rate));
        frame->tx_rates[0].idx = def_rate_idx;

        if (ctx->verbose >= 1) {
            fprintf(ctx->logfd, "Recv geneve pkt    "
                    " src: " MAC_FMT 
                    " dst: " MAC_FMT 
                    " phy: " MAC_FMT "\n", 
                    MAC_ARG(frame->wlan_src_addr),
                    MAC_ARG(frame->wlan_dst_addr),
                    MAC_ARG(frame->phyaddr));
        }

        if (ctx->wem_mode == true) {
            int src_id = 0;
            int snr = -90;
            double per;

            snr = get_snr(src_id);
            per = get_error_prob_from_snr(snr, frame->tx_rates[0].idx, 
                    2412, frame->data_len);
        }


        if (pdata->type == TX) {
            if (tslot_emu) {
                uint8_t *frame_type = frame->data;

                int rate = link_rate;
                if (ctx->opts->beacon == true && (*frame_type & 0x0f) == 8) {
                    rate = beacon_rate;
                }

                //cas_lock(&tslot_lock);
                pthread_mutex_lock(&tslot_lock);
                wait_sendtime(recv_len, rate, PLCP_11A);
                //cas_unlock(&tslot_lock);
                pthread_mutex_unlock(&tslot_lock);
            }
            if (ctx->mode == AST_NETLINK) {
                send_wlan(ctx, frame);
                if (ctx->opts->local_ack == FALSE) {
                    //if (pdata->flags == 0) {
                    //    uint8_t *dest_maddr = data + 16;
                    //    if (memcmp(dest_maddr, bcast_addr, 6) == 0) {
                    //        // no ack Broadcast
                    //        continue;
                    //    }
                    //    else if (memcmp(dest_maddr, mcast_addr, 3) == 0) {
                    //        // Multicast
                    //        continue;
                    //    }
                    //    else if (memcmp(dest_maddr, span_addr, 3) == 0) {
                    //        // Spanning tree(BPDU)
                    //        continue;
                    //    }
                    //}
                    uint8_t *gnv;
                    int pkt_len;
                    pdata->type = TX_ACK;
                    from.sin_port = htons(GNV_PORT);

                    gnv = gnv_alloc();
                    add_gnv_hdr(gnv, ctx->vni, GNV_WL_BRIDGE);
                    pkt_len = add_gnv_opt(gnv, 0, sizeof (struct packed_data), (uint8_t *)pdata);

                    if (tslot_emu) {
                        struct timespec wait_ack_t = {0, 0};
                        // tx_ack transmission time. 44us 
                        if (rate2ofdm_idx(link_rate)) {
                            // OFDM TX ACK
                            wait_ack_t.tv_nsec = 44000;
                        }
                        else if (rate2dsss_idx(link_rate)) {
                            // DSSS TX ACK
                            wait_ack_t.tv_nsec = 304000;
                        }
                        else {
                            // FHSS TC ACK
                            wait_ack_t.tv_nsec = 240000;
                        }
                        pthread_mutex_lock(&tslot_lock);
                        nanosleep(&wait_ack_t, NULL);
                        pthread_mutex_unlock(&tslot_lock);
                    }
                    sendto(ctx->gnv_sock, (void *)gnv, pkt_len + GNV_HDRLEN, 0, (struct sockaddr *)&daddr, addr_len);
                    gnv_free(gnv);
                }
            }
            else if (ctx->mode == AST_CDEV) {
                hwsim_mmap_send2wlan(ctx, frame);
                if (pdata->flags == HWSIM_TX_CTL_NO_ACK) {
                    continue;
                }
            }
        }
        else if (pdata->type == TX_ACK) {
            // send tx_ack to local interface
            //frame->signal = rate2signal(frame->tx_rates[0].idx);
            send_tx_ack(ctx, frame);
         }
        else {
            continue;
        }
    }
}

void *
recv_from_hwsim(void *param)
{
    struct asteroid_ctx *ctx = (struct asteroid_ctx *)param;

    init_nl(ctx);
    if (!ctx->indexer) {
        init_probability(ctx);
    }

    if(ctx->pif != NULL) {
        init_wlan2lan(ctx);
    }

    if (ctx->verbose >= 1) {
        fprintf(ctx->logfd, "Interface count: %d\n", ctx->ifnum);
        fflush(ctx->logfd);
    }

    if (in_ifhead) {
        int i;
        int ifr_sock;
        size_t if_namelen;
        struct ifreq ifr;
        struct iflist *ifp = NULL;
        ifp = in_ifhead;
        for(i = 0; i < ctx->ifnum; i++) {
            if_namelen = strlen(ifp->devname);
            if (if_namelen < sizeof(ifr.ifr_name)) {
                memcpy(ifr.ifr_name, ifp->devname, if_namelen);
                ifr.ifr_name[if_namelen] = 0;
            }
            else {
                fprintf(ctx->logfd, "interface name is too long\n");
                fflush(ctx->logfd);
                exit(1);
            }
            ifr_sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (ifr_sock == -1) {
                perror("socket");
                exit(1);
            }
            if (ioctl(ifr_sock, SIOCGIFHWADDR, &ifr) == -1) {
                perror("ioctl");
                close(ifr_sock);
                exit(1);
            }
            if (ifr.ifr_hwaddr.sa_family!=ARPHRD_ETHER) {
                fprintf(ctx->logfd, "not ethernet interface");
                fflush(ctx->logfd);
            }
            else {
                put_wlan_macaddr(ctx, phy_addr_default, i);
                if (ctx->verbose >= 1) {
                    fprintf(ctx->logfd, "local interface: %s, "
                            "id: %d, MAC Address: " MAC_FMT "\n",
                            ifp->devname, i, MAC_ARG(phy_addr_default.addr));
                }
            }
            ifp = ifp->next;
        }
    }

    int ret;
    ret = send_register_msg(ctx);
    if (ret != 0) {
        fprintf(ctx->logfd, "Cannot send_register_msg: %d\n", ret);
        fflush(ctx->logfd);
        exit(EXIT_FAILURE);
    }

    while (1) {
        nl_recvmsgs_default(ctx->sock);
    }

    free(ctx->sock);
    free(ctx->cb);
    free(ctx->cache);
    free(ctx->family);
}

struct hwsim_frame *frame_ = (struct hwsim_frame *)malloc(9000);
int
hwsim_mmap_send2lan(struct asteroid_ctx *ctx, struct mmap_mbuf *mbuf)
{
    ssize_t rate_size;
    uint8_t *wlan_src_addr, *wlan_dst_addr;
    struct hwsim_frame *frame = frame_;
    struct ieee80211_hdr *wlan_hdr;

    wlan_hdr = (struct ieee80211_hdr *)mbuf->data;
    wlan_dst_addr = wlan_hdr->addr1;
    wlan_src_addr = wlan_hdr->addr2;

    if (mbuf->len < 16) {
        return -1;
    }
    rate_size = sizeof (struct hwsim_tx_rate) * IEEE80211_TX_MAX_RATES;

    memcpy(frame->data, mbuf->data, mbuf->len);
    frame->data_len = mbuf->len;
    frame->flags = mbuf->hdr.flags;
    frame->cookie = mbuf->hdr.cookie;
    frame->freq = mbuf->hdr.freq;
    memcpy(frame->phyaddr, mbuf->hdr.transmitter, ETH_ALEN);
    memcpy(frame->wlan_src_addr, wlan_src_addr, ETH_ALEN);
    memcpy(frame->wlan_dst_addr, wlan_dst_addr, ETH_ALEN);
    frame->tx_rate_cnt = IEEE80211_TX_MAX_RATES;
    memcpy(frame->tx_rates, mbuf->hdr.tx_attempts, rate_size);
    frame->seq = 0;

    uint8_t *frame_type;
    frame_type = (uint8_t *)frame->data;

    if (ctx->verbose >= 1) {
        fprintf(ctx->logfd, "Recv from hwsim     src: " MAC_FMT "\n", 
                MAC_ARG(frame->wlan_src_addr));
        if (ctx->verbose >= 3) {
            pktdump(frame->data, frame->data_len);
        }
    }

/*
   int round;
   struct hwsim_tx_rate tx_rate;
   for (round = 0; round < IEEE80211_MAX_RATES_PER_TX; round++) {
   if (tx_rates[round].idx == -1) {
   break;
   }
   }
   round--;
   tx_rate.idx   = tx_rates[round].idx;
   tx_rate.count = tx_rates[round].count;
   */
    frame->tx_rates->idx = def_rate_idx;

    if (ctx->opts->tslot_emu) {
        int rate = link_rate;
        if (ctx->opts->beacon == true && (*frame_type & 0x0f) == 8) {
            rate = beacon_rate;
        }

        //cas_lock(&tslot_lock);
        pthread_mutex_lock(&tslot_lock);
        wait_sendtime(frame->data_len, rate, PLCP_11A);
        pthread_mutex_unlock(&tslot_lock);
        //cas_unlock(&tslot_lock);
    }

    if (ctx->pif) {
        /*
           int i;
           struct timeval *tv;
           for (i = 0; i >= MAX_POOL; i++) {
           if (ppool[i].used == true) {
           continue;
           }
           gettimeofday(tv, NULL);
           ppool[i].used = true;
           ppool[i].tv = tv;
           break;
           }
           */
        send_lan(ctx, frame);
    }
    //wlan2wlan(nlmsg, wlan_src_addr, data, len, flags, tx_rate, cookie);

    // IEEE 802.11a
    //   slot time: 9us
    //   SIFS time: 16us
    //   DIFS time: 34us
    //   minimam contention window: 15
    // backoff time average
    //   backoff_t = slot_time * (min_contention_window / 2) = 67.5us
    if (tslot_emu) {
        struct timespec backoff_t;
        backoff_t.tv_sec = 0;
        backoff_t.tv_nsec = 67500;
        nanosleep(&backoff_t, NULL);
    }

    return 0;
}

void *
read_from_hwsim_mmap(void *param)
{
    int ret;
    int mmap_prot;
    char *mem = NULL;
    char *buf;
    struct mmap_mbuf *mbuf;
    struct asteroid_ctx *ctx = (struct asteroid_ctx *)param;

    fprintf(ctx->logfd, "[%s] PID: %ld\n", __func__, syscall(SYS_gettid));

    if(ctx->pif != NULL) {
        init_wlan2lan(ctx);
    }

    mmap_fd = open(DEVICE_FILENAME, O_RDWR|O_NDELAY);
    if (mmap_fd < 0) {
        printf("failed to open the character device\n");
        goto out;
    }

    if(mmap_fd >= 0) {
        mmap_prot =  PROT_READ | PROT_WRITE;
        mem = (char *)mmap(0, PAGE_SIZE, mmap_prot, MAP_SHARED, mmap_fd, 0);
        munmap(mem, PAGE_SIZE);

        close(mmap_fd);
    }
    else {
        ERROR("Cannot open %s. Error: %s\n", DEVICE_FILENAME, strerror(errno));
    }

    mmap_fd = open(DEVICE_FILENAME, O_RDWR|O_NDELAY);
    if (mmap_fd < 0) {
        ERROR("Cannot open %s. Error: %s\n", DEVICE_FILENAME, strerror(errno));
        goto out;
    }

    if (!ctx->indexer) {
        init_probability(ctx);
    }

    put_wlan_macaddr(ctx, phy_addr_default, 0);
    buf = (char *)malloc(PAGE_SIZE);
    for (;;) {
        ret = read(mmap_fd, buf, PAGE_SIZE);
        if (ret == 0) {
            usleep(1);
            continue;
        }
        if (unlikely(ret < 0)) {
            printf("read error: %d. errno: %s\n", ret, strerror(errno));
            ret = errno;
        }
        mbuf = (struct mmap_mbuf *)buf;
        if (ctx->verbose >= 2) {
            printf("len: %d\n", ret);
            printf("mbuf[%d] len: %d\n", mbuf->id, mbuf->len);
        }
        if (ctx->verbose == 3) {
            pktdump((uint8_t *)&mbuf->hdr, sizeof (struct hwsim_mmap_header));
            pktdump((uint8_t *)mbuf->data, mbuf->len);
        }
        hwsim_mmap_send2lan(ctx, mbuf);
    }
    free(buf);

out:
    return NULL;
}

struct mmap_mbuf_c {
	int flag;
	struct mmap_mbuf mbuf;
};

struct mmap_mbuf_c mbufc;

void *
read_from_hwsim_mmap2(void *param)
{
    int ret;
    int mmap_prot;
    char *mem = NULL;
    char *buf;
    struct mmap_mbuf *mbuf;
    struct asteroid_ctx *ctx = (struct asteroid_ctx *)param;

    fprintf(ctx->logfd, "[%s] PID: %ld\n", __func__, syscall(SYS_gettid));

    if(ctx->pif != NULL) {
        init_wlan2lan(ctx);
    }

    mmap_fd = open(DEVICE_FILENAME, O_RDWR|O_NDELAY);
    if (mmap_fd < 0) {
        printf("failed to open the character device\n");
        goto out;
    }

    if(mmap_fd >= 0) {
        mmap_prot = PROT_READ | PROT_WRITE;
        mem = (char *)mmap(0, PAGE_SIZE, mmap_prot, MAP_SHARED, mmap_fd, 0);
        printf("%s", mem);
        munmap(mem, PAGE_SIZE);

        close(mmap_fd);
    }
    else {
        ERROR("Cannot open %s. Error: %s\n", DEVICE_FILENAME, strerror(errno));
    }

    mmap_fd = open(DEVICE_FILENAME, O_RDWR|O_NDELAY);
    if (mmap_fd < 0) {
        ERROR("Cannot open %s. Error: %s\n", DEVICE_FILENAME, strerror(errno));
        goto out;
    }

    if (!ctx->indexer) {
        init_probability(ctx);
    }
    //init_nl(ctx);
    //ret = send_register_msg(ctx);
    //if (ret != 0) {
    //    fprintf(ctx->logfd, "Cannot send_register_msg: %d\n", ret);
    //    fflush(ctx->logfd);
    //    exit(EXIT_FAILURE);
    //}

    put_wlan_macaddr(ctx, phy_addr_default, 0);

    //ret = write(fd, "abcd", strlen("abcd"));
    //if (ret < 0) {
    //    printf("write error!\n");
    //    ret = errno;
    //    goto out;
    //}

    buf = (char *)malloc(PAGE_SIZE);
    for (;;) {
        ret = read(mmap_fd, buf, PAGE_SIZE);
        if (ret == 0) {
            usleep(1);
            continue;
        }
        if (ret < 0) {
            printf("read error: %d. errno: %s\n", ret, strerror(errno));
            ret = errno;
        }
        mbuf = (struct mmap_mbuf *)buf;
        if (ctx->verbose >= 2) {
            printf("len: %d\n", ret);
            printf("mbuf[%d] len: %d\n", mbuf->id, mbuf->len);
        }
        if (ctx->verbose == 3) {
            pktdump((uint8_t *)&mbuf->hdr, sizeof (struct hwsim_mmap_header));
            pktdump((uint8_t *)mbuf->data, mbuf->len);
        }
        if (mbufc.flag == 0 ) {
		    memcpy(&(mbufc.mbuf), mbuf, sizeof (struct mmap_mbuf));
            pthread_mutex_lock(&gnv_lock);
            mbufc.flag = 1;
            pthread_mutex_unlock(&gnv_lock);
        }
        else {
            continue;
        }
    }
    free(buf);

out:
    return NULL;
}

void *
send_geneve(void *param)
{
    struct asteroid_ctx *ctx = (struct asteroid_ctx *)param;

    for (;;) {
        if (mbufc.flag == 1) {
            hwsim_mmap_send2lan(ctx, &(mbufc.mbuf));
            pthread_mutex_lock(&gnv_lock);
            mbufc.flag = 0;
            pthread_mutex_unlock(&gnv_lock);
        }
    }
}


int
asteroid_loop(struct asteroid_ctx *ctx)
{
    pthread_t hwsim_th;
    pthread_t cdev_th;
    pthread_t remote_th;

    if (ctx->mode == AST_NETLINK) {
        if (pthread_create(&hwsim_th, NULL, recv_from_hwsim, (void *)ctx) != 0) {
            perror("pthread_create");
        }
    }
    else if (ctx->mode == AST_CDEV) {
        if (pthread_create(&cdev_th, NULL, read_from_hwsim_mmap, (void *)ctx) != 0) {
            perror("pthread_create");
        }
    }

    pthread_t geneve_th;
    if (pthread_create(&geneve_th, NULL, send_geneve, (void *)ctx) != 0) {
        perror("pthread_create");
    }

    if(ctx->pif != NULL) {
        if (pthread_create(&remote_th, NULL, recv_from_lan, (void *)ctx) != 0) {
            perror("pthread_create");
        }
    }

    while (1) {
        sleep(1);
    }

    return 0;
}

void
init_asteroid_ctx(struct asteroid_ctx *ctx)
{
    ctx->ifnum = 0;
    ctx->pif = NULL;
    ctx->o_port = 0;
    ctx->verbose = 0;
    ctx->wem_mode = false;
    ctx->daemonize = false;

    ctx->vni = DEFAULT_VNI;

    ctx->mode = AST_NETLINK;

    ctx->opts = (struct asteroid_options *)malloc(sizeof (struct asteroid_options));
    ctx->opts->local_ack = true;
}

void
set_mode(struct asteroid_ctx *ctx, char *optarg)
{
    if (strncmp(optarg, "netlink", sizeof ("netlink")) == 0) {
        ctx->mode = AST_NETLINK;
    }
    else if (strncmp(optarg, "cdev", sizeof ("cdev")) == 0) {
        ctx->mode = AST_CDEV;
    }
    else {
        ctx->mode = AST_NETLINK;
    }
}

int
main(int argc, char **argv)
{
    int opt;
    struct asteroid_ctx *ctx;

    ctx = (struct asteroid_ctx *)malloc(sizeof (struct asteroid_ctx));
    init_asteroid_ctx(ctx);

    while ((opt = getopt(argc, argv, "abc:dhi:l:f:m:p:P:r:vw:W")) != -1) {
        switch (opt) {
            case 'a':
                ctx->opts->local_ack = FALSE;
                break;
            case 'b':
                ctx->opts->beacon = true;
                break;
            case 'c':
                ctx->conf_file = optarg;
                break;
            case 'd':
                ctx->daemonize = true;
                break;
            case 'f':
                ctx->logfile = optarg;
                break;
            case 'h':
                usage();
                return 0;
            case 'i':
                ctx->vni = atoi(optarg);
                break;
            case 'l':
                offset_t = atoi(optarg);
                break;
            case 'm':
                set_mode(ctx, optarg);
                break;
            case 'p':
                ctx->pif = optarg;
                break;
            case 'P':
                ctx->o_addr = optarg;
                break;
            case 'r':
                tslot_emu = true;
                link_rate = atoi(optarg);
                break;
            case 'v':
                ctx->verbose++;
                break;
            case 'w':
                if (ctx->ifnum == 0) {
                    in_ifhead = MALLOC(struct iflist, 1);
                    in_iflist = in_ifhead;
                }
                else {
                    in_iflist->next = MALLOC(struct iflist, 1);
                    in_iflist = in_iflist->next;
                }
                strcpy(in_iflist->devname, optarg);
                ctx->ifnum++;
                break;
            case 'W':
                ctx->wem_mode = true;
                break;
            default:
                usage();
                return -1;
        }
    }

    if (!ctx->logfile && ctx->daemonize == FALSE) {
        ctx->logfd = stdout;
    }
    else if (ctx->logfile) {
        ctx->logfd = fopen(ctx->logfile, "a");
        if (!ctx->logfd) {
            fprintf(stderr,  "Cannot open logfile.");
            ctx->logfd = stdout;
        }
    }
    else {
        ctx->logfd = fopen("/dev/null", "w");
    }

    ctx->modulation.ofdm_idx = rate2ofdm_idx(link_rate);
    ctx->modulation.dsss_idx = rate2dsss_idx(link_rate);
    if (ctx->modulation.ofdm_idx == -1 && ctx->modulation.dsss_idx == -1) {
        fprintf(ctx->logfd, "Invalid Rate: %d\n", link_rate);        
        return -1;
    }
    if (ctx->conf_file) {
        in_ifhead = NULL;
        if (parse_conf(ctx) != 0) {
            fprintf(ctx->logfd, "Cannot parse config file\n");
            return -1;
        }
    }
    if (ctx->ifnum == 0) {
        usage();
        return -1;
    }
    if (ctx->o_port == 0) {
        ctx->o_port = GNV_PORT;
    }
    if (ctx->daemonize == true) {
        if (daemon(0, 0) == 0) {
            return asteroid_loop(ctx);
        }
        else {
            perror("daemon");
        }
    }
    else {
        return asteroid_loop(ctx);
    }
}


