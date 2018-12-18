#include <iostream>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>
#include <linux/if_ether.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <ifaddrs.h>
#include <getopt.h>
#include <string>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "asteroid.hpp"
#include "geneve.hpp"
#include "config.hpp"
#include "hwsim.hpp"

struct nl_sock *nlsock;
struct nl_cb *cb;
struct nl_cache *cache;
struct genl_family *family;
int in_ifnum = 0;
struct iflist *in_ifhead = NULL;
struct iflist *in_iflist = NULL;
char *pif = NULL;
char *outer_addr = NULL;
uint16_t out_port;
static int array_size = 0;
static struct wlan_macaddr *indexer;
int daemon_flag = FALSE;
FILE *logfd = NULL;
int write_vaddr = 0;

int verbose = FALSE;
int print_pkt = FALSE;
int send_sock;
struct sockaddr_in daddr;
struct sockaddr_in laddr;

struct pkt_pool *ppool;
uint32_t sed_num = 0;

int beacon     = FALSE;
int tslot_emu  = FALSE;
pthread_mutex_t tslot_lock = PTHREAD_MUTEX_INITIALIZER;
int local_ack  = FALSE;
int link_rate = 54;
int def_rate_idx = 0;
int ofdm_idx = -1;
int dsss_idx = -1;
uint32_t offset_t = 0;
int beacon_rate = 1;
uint32_t vni = DEFAULT_VNI;

void
usage()
{
    fprintf(stderr, "Usage: asteroid -w <WIRELESS_IFNAME> -p <PHYSICAL_IFNAME> [-i VNI] [-l <LOGFILE> [-t -r <RATE> [-l <LATENCY>]] [-v] [-x] [-h]\n");
    fprintf(stderr, "    -c CONF_FILE           : wireless interface file\n");
    fprintf(stderr, "    -w WIRELESS_IFNAME     : wireless interface\n");
    fprintf(stderr, "    -p PHYSICAL_IFNAME     : ethernet interface\n");
    fprintf(stderr, "    -P DESTINATION_ADDRESS : Destination IP Address\n");
    fprintf(stderr, "    -i VNI                 : Geneve Virtual Network Identifier. default: 5001\n");
    fprintf(stderr, "    -t                     : enable transmission time calculation. require -r\n");
    fprintf(stderr, "    -r RATE[Mbps]          : emulation link speed. required -t.\n");
    fprintf(stderr, "                                RATE: 6 9 12 18 24 36 48 54\n");
    fprintf(stderr, "    -l LATENCY[us]         : offset transmission time. latency between servers.\n");
    fprintf(stderr, "    -v                     : verbose mode\n");
    fprintf(stderr, "    -f                     : log file name\n");
    fprintf(stderr, "    -x                     : print packet dump. required -v\n");
    fprintf(stderr, "    -h                     : help\n");
}

static void
pktdump(uint8_t* buf, int len)
{
/*
    if (print_pkt == FALSE) {
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

void *
pkt_scheduler(void *params)
{
    int i;
    struct timeval tv;
    ppool = (struct pkt_pool *)malloc(sizeof (struct pkt_pool) * MAX_POOL);
    if (!ppool) {
        fprintf(logfd, "[pkt_scheduler] Cannot allocate memory\n");
        fflush(logfd);
        exit(1);
    }
    memset(ppool, 0, sizeof (struct pkt_pool) * MAX_POOL);

    while (1) {
        gettimeofday(&tv, NULL);
        for (i = 0; i >= MAX_POOL; i++) {
            if (ppool[i].used == FALSE) {
                continue;
            }
            
            if ((tv.tv_sec - ppool[i].tv->tv_sec) >= 1) {
                memset(&ppool[i], 0, sizeof (struct pkt_pool));
            }
        }
        sleep(1);
    }

    free(ppool);
}

void
print_wlan_macaddr(struct wlan_macaddr *addr, int cr)
{
    fprintf(logfd, "\t%02x:%02x:%02x:%02x:%02x:%02x", 
            addr->addr[0], addr->addr[1], addr->addr[2],
            addr->addr[3], addr->addr[4], addr->addr[5]);
    if (cr) {
        fprintf(logfd, "\n");
    }
    fflush(logfd);
}

void
dump_macaddress(int ifnum)
{
    int i;
    void *ptr = indexer;
    for (i = 0; i < ifnum; i++) {
        print_wlan_macaddr((struct wlan_macaddr *)ptr, 1);
        ptr = (char *)ptr + sizeof (struct wlan_macaddr);
    }
}

void
put_wlan_macaddr(struct wlan_macaddr addr, int pos)
{   
    int i;
    void *ptr = indexer;
    
    for (i = 0; i < pos ; i++) {
        ptr = (char *)ptr + sizeof (struct wlan_macaddr);
    }
    memcpy(ptr, &addr, sizeof (struct wlan_macaddr));
}  

int
init_probability(int size) {

    array_size = size;
    indexer = (struct wlan_macaddr *)malloc(sizeof (struct wlan_macaddr) * array_size);

    if (indexer == NULL) {
        fprintf(logfd, "Problem allocating vector");
        fflush(logfd);
        exit(1);
    }

    return 0;
}

int
parse_conf(char *conf_file)
{
    int i;
    int ifnum = 0;
    struct wlan_macaddr addr;
    struct node_data *nlist;

    memset(&addr, 0, sizeof (struct wlan_macaddr));

    ifnum = get_node_cnt(conf_file);
    nlist = create_node_list(conf_file, ifnum);
    dump_node_list(nlist, ifnum);

    init_probability(ifnum);
    void *ptr = indexer;
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

    return ifnum;
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
get_wlan_macaddr(int pos) {

    void * ptr = indexer;
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

    print_wlan_macaddr(&mac, 1);

    return mac;
} 

int
send_lan(void *data, uint32_t len, struct wlan_macaddr src, struct wlan_macaddr tx, uint32_t flags, struct hwsim_tx_rate tx_rates, uint64_t cookie, int seq)
{
    int pkt_len;
    uint8_t type = 0;
    struct packed_data pdata;
    uint8_t *gnv;

    gnv = gnv_alloc();
    add_gnv_hdr(gnv, vni, GNV_WL_BRIDGE);

    pdata.type = TX;
    pdata.src = src;
    pdata.src = tx;
    pdata.flags = flags;
    pdata.tx_rates = tx_rates;
    pdata.cookie = cookie;
    pdata.seq = seq;

    pdata.tx_rates.idx = def_rate_idx;

    pkt_len = add_gnv_opt(gnv, type, 32, (uint8_t *)&pdata);
    if (pkt_len == -1) {
        fprintf(logfd, "cannot add option header\n");
        fflush(logfd);
        gnv_free(gnv);

        return -1;
    }

    pkt_len = add_gnv_opt(gnv, 1, 4, (uint8_t *)data);
    if (pkt_len == -1) {
        fprintf(logfd, "cannot add option header\n");
        fflush(logfd);
        gnv_free(gnv);

        return -1;
    }

    pkt_len = add_gnv_payload(gnv, (uint8_t *)data + 4, len - 4);
    if (pkt_len == -1) {
        fprintf(logfd, "cannot add original frame\n");
        fflush(logfd);
        gnv_free(gnv);

        return -1;
    }

    if (verbose == TRUE) {
        fprintf(logfd, "---> Send external from: ");
        print_wlan_macaddr(&src, 1);
        fflush(logfd);
    }

    if (sendto(send_sock, (void *)gnv, pkt_len, 0, (struct sockaddr *)&daddr, sizeof (daddr)) < 0) {
        perror("sendto");
        gnv_free(gnv);

        return -1;
    }

    gnv_free(gnv);

    return 0;
}

int
send_wlan(struct wlan_macaddr *src, struct wlan_macaddr *tx,
        char *data, int len, 
        uint32_t flags, struct hwsim_tx_rate *tx_rates, 
        uint64_t cookie)
{
    int rc, i;
    struct wlan_macaddr *dst;
    struct nl_msg *nlmsg;

    tx_rates->idx = def_rate_idx;

    for (i = 0; i < in_ifnum; i++) {
        nlmsg = nlmsg_alloc();
        if (!nlmsg) {
            fprintf(logfd, "Error allocating new message MSG!\n"); 
            fflush(logfd);
            nlmsg_free(nlmsg);
            return -1;
        }

        dst = get_wlan_macaddr(i);
        if (memcmp(src, dst, sizeof (struct wlan_macaddr)) == 0) {
            nlmsg_free(nlmsg);
            continue;
        }

        if (verbose == TRUE) {
            fprintf(logfd, "---> Send local    from: ");
            print_wlan_macaddr(src, 0);
            fprintf(logfd, " to: ");
            print_wlan_macaddr(dst, 1);
            fflush(logfd);
            if (print_pkt) {
                pktdump((uint8_t *)data, len);
            }
        }

        genlmsg_put(nlmsg, NL_AUTO_PID, NL_AUTO_SEQ, genl_family_get_id(family), 
                0, NLM_F_REQUEST, HWSIM_CMD_FRAME, VERSION_NR);
        rc = nla_put(nlmsg, HWSIM_ATTR_ADDR_RECEIVER, sizeof (struct wlan_macaddr), dst);
        if (rc != 0) {
            fprintf(logfd, "Error nla_put HWSIM_ATTR_ADDR_RECEIVER filling payload\n");
            fprintf(logfd, "send: ");
            print_wlan_macaddr(src, 0);
            fprintf(logfd, " -> ");
            print_wlan_macaddr(dst, 1);
            fflush(logfd);
            nlmsg_free(nlmsg);
            continue;
        }
        rc = nla_put(nlmsg, HWSIM_ATTR_FRAME, len, data);
        if (rc != 0) {
            fprintf(logfd, "Error nla_put HWSIM_ATTR_FRAME filling payload\n");
            fflush(logfd);
            nlmsg_free(nlmsg);
            continue;
        }
        rc = nla_put_u32(nlmsg, HWSIM_ATTR_RX_RATE, tx_rates->idx);
        if (rc != 0) {
            fprintf(logfd, "Error nla_put_u32 HWSIM_ATTR_RX_RATE filling payload\n");
            fflush(logfd);
            nlmsg_free(nlmsg);
            continue;
        }
        rc = nla_put_u32(nlmsg, HWSIM_ATTR_SIGNAL, rate2signal(tx_rates->idx));
        if (rc != 0) {
            fprintf(logfd, "Error nla_put_u32 SIGNAL filling payload\n");
            fflush(logfd);
            nlmsg_free(nlmsg);
            continue;
        }
        
        rc = nl_send_auto_complete(nlsock, nlmsg);
        if (rc < 0) {
            fprintf(logfd, "Error nl_send_auto_complete filling payload: %d\n", rc);
            fflush(logfd);
        }
        nlmsg_free(nlmsg);
    }

    return 0;
}
 
int
send_tx_ack(struct nl_msg *nlmsg, struct wlan_macaddr *src, unsigned int flags, int signal,
        struct hwsim_tx_rate *tx_attempts, unsigned long cookie)
{
    int rc;
    
    nlmsg = nlmsg_alloc();
    flags |= HWSIM_TX_STAT_ACK;
    
    genlmsg_put(nlmsg, NL_AUTO_PID, NL_AUTO_SEQ, genl_family_get_id(family),
            0, NLM_F_REQUEST, HWSIM_CMD_TX_INFO_FRAME, VERSION_NR);
    
    rc = nla_put(nlmsg, HWSIM_ATTR_ADDR_TRANSMITTER, sizeof (struct wlan_macaddr), src);
    rc = nla_put_u32(nlmsg, HWSIM_ATTR_FLAGS, flags);
    rc = nla_put_u32(nlmsg, HWSIM_ATTR_SIGNAL, signal);
    rc = nla_put(nlmsg, HWSIM_ATTR_TX_INFO, IEEE80211_MAX_RATES_PER_TX * sizeof (struct hwsim_tx_rate), tx_attempts);
    rc = nla_put_u64(nlmsg, HWSIM_ATTR_COOKIE, cookie);

    if(rc != 0) {
        fprintf(logfd, "Error filling payload\n");
        fflush(logfd);
        nlmsg_free(nlmsg);
        return -1;
    }

    if (verbose == TRUE) {
        fprintf(logfd, "----> Send Ack     to:   ");
        print_wlan_macaddr(src, 1);
        fflush(logfd);
    }

    nl_send_auto_complete(nlsock, nlmsg);
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

    if (verbose == TRUE) {
        fprintf(logfd, "--> transmission time: %u us.\n", delay_t / 1000);
    }
    fflush(logfd);

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

    fprintf(logfd, "wait time: %lu\n", stime.tv_nsec);
    fflush(logfd);
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
    struct nlattr *attrs[HWSIM_ATTR_MAX + 1];
    struct nlmsghdr *nlh = nlmsg_hdr(nlmsg);
    struct genlmsghdr *gnlh = (struct genlmsghdr *)nlmsg_data(nlh);
    struct wlan_macaddr *src, *tx;

    if(gnlh->cmd == HWSIM_CMD_FRAME) {
        genlmsg_parse(nlh, 0, attrs, HWSIM_ATTR_MAX, NULL);
        if (attrs[HWSIM_ATTR_ADDR_TRANSMITTER]) {
            char *data = (char *)nla_data(attrs[HWSIM_ATTR_FRAME]);
            uint32_t len = nla_len(attrs[HWSIM_ATTR_FRAME]);

            if (write_vaddr) {
                tx = (struct wlan_macaddr *)nla_data(attrs[HWSIM_ATTR_ADDR_TRANSMITTER]);
            }
            else {
                tx = (struct wlan_macaddr *)(data + 10);
            }
            uint32_t flags = nla_get_u32(attrs[HWSIM_ATTR_FLAGS]);
            struct hwsim_tx_rate *tx_rates = (struct hwsim_tx_rate *)nla_data(attrs[HWSIM_ATTR_TX_INFO]);
            uint64_t cookie = nla_get_u64(attrs[HWSIM_ATTR_COOKIE]);

            src = (struct wlan_macaddr *)(data + 10);
            uint8_t *frame_type;
            frame_type = (uint8_t *)data;

            if (verbose == TRUE) {
                fprintf(logfd, "Recv local        from: ");
                print_wlan_macaddr(src, 1);
                fflush(logfd);
                if (print_pkt) {
                    pktdump((uint8_t *)data, len);
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
            //tx_rates->idx = def_rate_idx;

            if (tslot_emu) {
                int rate = link_rate;
                if (beacon == TRUE && (*frame_type & 0x0f) == 8) {
                    rate = beacon_rate;
                }

                //cas_lock(&tslot_lock);
                pthread_mutex_lock(&tslot_lock);
                wait_sendtime(len, rate, PLCP_11A);
                pthread_mutex_unlock(&tslot_lock);
                //cas_unlock(&tslot_lock);
            }

            if (pif) {
                /*
                int i;
                struct timeval *tv;
                for (i = 0; i >= MAX_POOL; i++) {
                    if (ppool[i].used == TRUE) {
                        continue;
                    }
                    gettimeofday(tv, NULL);
                    ppool[i].used = TRUE;
                    ppool[i].tv = tv;
                    break;
                }
                */
                send_lan((void *)data, len, *src, *tx, flags, *tx_rates, cookie, 0);
            }
            //wlan2wlan(nlmsg, src, data, len, flags, tx_rate, cookie);

            if (local_ack == TRUE || flags == HWSIM_TX_CTL_NO_ACK) {
                flags |= HWSIM_TX_STAT_ACK;
                send_tx_ack(nlmsg, tx, flags, rate2signal(tx_rates->idx), tx_rates, cookie);
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
send_register_msg()
{
    struct nl_msg *nlmsg;
    nlmsg = nlmsg_alloc();
    if (!nlmsg) {
        return -1;
    }

    genlmsg_put(nlmsg, NL_AUTO_PID, NL_AUTO_SEQ, genl_family_get_id(family), 0, NLM_F_REQUEST, 1, 1);
    nl_send_auto_complete(nlsock, nlmsg);
    nlmsg_free(nlmsg);

    return 0;
}

void
init_nl()
{
    cb = nl_cb_alloc(NL_CB_CUSTOM);
    if (!cb) {
        printf("cannot alloc cb\n");
        exit(EXIT_FAILURE);
    }

    nlsock = nl_socket_alloc_cb(cb);
    if (!nlsock) {
        printf("cannot alloc socket\n");
        exit(EXIT_FAILURE);
    }

    nl_socket_set_nonblocking(nlsock);
    genl_connect(nlsock);
    genl_ctrl_alloc_cache(nlsock, &cache);

    family = genl_ctrl_search_by_name(cache, "MAC80211_HWSIM");
    if (!family) {
        printf("cannot search family\n");
        exit(EXIT_FAILURE);
    }

    nl_cb_set(cb, NL_CB_MSG_IN, NL_CB_CUSTOM, wlan_frame_cb, NULL);
}

int
init_wlan2lan(char *pif, uint16_t port)
{
    int bcast = 0;
    int ifr_sock;
    uint32_t if_namelen;
    struct ifreq ifr;

    fprintf(logfd, "outgoing interface: %s\n", pif);
    fflush(logfd);
    ifr_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (ifr_sock == -1) {
        perror("socket");
        exit(1);
    }
    if_namelen = strlen(pif);
    if (if_namelen < sizeof(ifr.ifr_name)) {
        memcpy(ifr.ifr_name, pif, if_namelen);
        ifr.ifr_name[if_namelen] = 0;
    }
    if (ioctl(ifr_sock, SIOCGIFADDR, &ifr) == -1) {
        perror("ioctl");
        close(ifr_sock);
        exit(1);
    }
    laddr.sin_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;

    if (!outer_addr) {
		if (ioctl(ifr_sock, SIOCGIFBRDADDR, &ifr) < 0) {
    	    perror("ioctl");
    	    close(ifr_sock);
    	    exit(1);
		}
        bcast = 1;
        outer_addr = (char *)malloc(INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &((struct sockaddr_in *)(&ifr.ifr_broadaddr))->sin_addr, outer_addr, INET_ADDRSTRLEN);
	}
    fprintf(logfd, "destination: %s\n", outer_addr);

    send_sock = socket(AF_INET, SOCK_DGRAM, 0);
    daddr.sin_family = AF_INET;
    daddr.sin_port = htons(GNV_PORT);
    daddr.sin_addr.s_addr = inet_addr(outer_addr);

    if (bcast == 1) {
        if (setsockopt(send_sock, SOL_SOCKET, SO_BROADCAST, &bcast, sizeof (bcast)) < 0) {
            perror("setsockopt");
            return -1;
        }
    }


    return 0;
}

void *
recv_from_lan(void *param)
{
    void *buf;
    int recv_sock;
    int len, recv_len;
    struct sockaddr_in addr;
    struct sockaddr_in from;
    socklen_t addr_len = sizeof(struct sockaddr_in);

    buf = malloc(MAX_BUF);
    recv_sock = socket(AF_INET, SOCK_DGRAM, 0);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(GNV_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(recv_sock, (struct sockaddr *)&addr, sizeof (addr));
    memset(buf, 0, MAX_BUF);

    //unsigned char bcast_addr[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    //unsigned char mcast_addr[] = { 0x01, 0x00, 0x5e };
    //unsigned char span_addr[] =  { 0x01, 0x80, 0xc2 };

    while (TRUE) {
        //recv_len = recv(recv_sock, buf, MAX_BUF, 0);
        recv_len = recvfrom(recv_sock, buf, MAX_BUF, 0, (struct sockaddr *)&from, &addr_len);
        if (recv_len == 0) {
            fprintf(logfd, "[recv_from_lan] receive length 0.\n");
            continue;
        }
        // 16777343 = 127.0.0.1;
        if ((from.sin_addr.s_addr == 16777343) || (laddr.sin_addr.s_addr == from.sin_addr.s_addr)) {
            continue;
        }

        // Geneve like pakcet.
        struct geneve_header *gnv_hdr = (struct geneve_header *)buf;
        if (vni != get_gnv_vni(gnv_hdr)) {
            // Drop different VNI frame;
            if (verbose == TRUE) {
                fprintf(logfd, "[recv_from_lan] Different VNI\n");
            }
            continue;
        }
        if (ntohs(gnv_hdr->proto_type) != GNV_WL_BRIDGE) {
            // Drop different proto type;
            if (verbose == TRUE) {
                fprintf(logfd, "[recv_from_lan] Invalid protocol type\n");
            }
            continue;
        }

        struct geneve_option *gnv_opt;
        gnv_opt = get_gnv_opt((uint8_t *)buf);
        struct packed_data *pdata = (struct packed_data *)(gnv_opt + 1);

        uint8_t *data;
        data = (uint8_t *)buf + GNV_HDRLEN + (gnv_hdr->opt_len * 4) - 4;
        len = recv_len - GNV_HDRLEN - (gnv_hdr->opt_len * 4) + 4;

        struct wlan_macaddr *src = &(pdata->src);
        struct wlan_macaddr *tx = &(pdata->tx);
        struct hwsim_tx_rate *tx_rates = &(pdata->tx_rates);
        tx_rates->idx = def_rate_idx;

        if (verbose == TRUE) {
            fprintf(logfd, "Recv external     from: ");
            print_wlan_macaddr(src, 1);
            fflush(logfd);
        }

        if (pdata->type == TX) {
            if (tslot_emu) {
                uint8_t *frame_type;
                frame_type = (uint8_t *)data;

                int rate = link_rate;
                if (beacon == TRUE && (*frame_type & 0x0f) == 8) {
                    rate = beacon_rate;
                }

                //cas_lock(&tslot_lock);
                pthread_mutex_lock(&tslot_lock);
                wait_sendtime(recv_len, rate, PLCP_11A);
                //cas_unlock(&tslot_lock);
                pthread_mutex_unlock(&tslot_lock);
            }
            send_wlan(src, tx, (char *)data, len, pdata->flags, tx_rates, pdata->cookie);
            if (verbose == TRUE) {
                fprintf(logfd, "----> Send to local interface\n");
                fflush(logfd);
            }
            if (pdata->flags == HWSIM_TX_CTL_NO_ACK) {
                continue;
            }
            //if ((pdata->flags == 0 || pdata->flags == HWSIM_TX_CTL_REQ_TX_STATUS) && local_ack == FALSE) {
            if (local_ack == FALSE) {
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
                add_gnv_hdr(gnv, vni, GNV_WL_BRIDGE);
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
                sendto(send_sock, (void *)gnv, pkt_len, 0, (struct sockaddr *)&daddr, addr_len);
                gnv_free(gnv);
                if (verbose == TRUE) {
                    fprintf(logfd, "----> Send ACK to remote interface\n");
                    fflush(logfd);
                }
            }
        }
        else if (pdata->type == TX_ACK) {
            // send tx_ack to local interface
            int signal;
            signal = rate2signal(pdata->tx_rates.idx);
            send_tx_ack(NULL, &(pdata->src), pdata->flags, signal, &(pdata->tx_rates), pdata->cookie);
            if (verbose == TRUE) {
                fprintf(logfd, "----> Send ACK to local interface\n");
                fflush(logfd);
            }
         }
        else {
            continue;
        }
    }

    free(buf);
}

void *
recv_from_hwsim(void *param)
{

    init_nl();
    if (!indexer) {
        init_probability(in_ifnum);
    }

    if(pif != NULL) {
        init_wlan2lan(pif, out_port);
    }

    if (verbose == TRUE) {
        fprintf(logfd, "Interface count: %d\n", in_ifnum);
        fflush(logfd);
    }

    if (in_ifhead) {
        int i;
        int ifr_sock;
        size_t if_namelen;
        struct ifreq ifr;
        struct iflist *ifp = NULL;
        ifp = in_ifhead;
        for(i = 0; i < in_ifnum; i++) {
            if_namelen = strlen(ifp->devname);
            if (if_namelen < sizeof(ifr.ifr_name)) {
                memcpy(ifr.ifr_name, ifp->devname, if_namelen);
                ifr.ifr_name[if_namelen] = 0;
            }
            else {
                fprintf(logfd, "interface name is too long\n");
                fflush(logfd);
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
                fprintf(logfd, "not ethernet interface");
                fflush(logfd);
            }

            if (write_vaddr) {
                struct wlan_macaddr *mac = (struct wlan_macaddr *)ifr.ifr_hwaddr.sa_data;
                put_wlan_macaddr(*mac, i);
                if (verbose == TRUE) {
                    fprintf(logfd, "local interface: %s, MAC Address: ", ifp->devname);
                    print_wlan_macaddr((struct wlan_macaddr *)mac, 1);
                    fflush(logfd);
                }
            }
            else {
                struct wlan_macaddr mac;
                mac.addr[0] = 0x42;
                mac.addr[1] = 0;
                mac.addr[2] = 0;
                mac.addr[3] = 0;
                mac.addr[4] = 0;
                mac.addr[5] = 0;
                put_wlan_macaddr(mac, i);
                if (verbose == TRUE) {
                    fprintf(logfd, "local interface: %s, MAC Address: ", ifp->devname);
                    print_wlan_macaddr((struct wlan_macaddr *)&mac, 1);
                    fflush(logfd);
                }
            }
            ifp = ifp->next;
        }
    }

    int ret;
    ret = send_register_msg();
    if (ret != 0) {
        fprintf(logfd, "Cannot send_register_msg: %d\n", ret);
        fflush(logfd);
        exit(EXIT_FAILURE);
    }

    while (1) {
        nl_recvmsgs_default(nlsock);
    }

    free(nlsock);
    free(cb);
    free(cache);
    free(family);
}

int
asteroid_loop()
{
    pthread_t local_th;
    pthread_t remote_th;

    //pthread_t pkt_sched;
    //if (pthread_create(&pkt_sched, NULL, pkt_scheduler, NULL) != 0) {
    //    perror("pthread_create");
    //}

    if (pthread_create(&local_th, NULL, recv_from_hwsim, NULL) != 0) {
        perror("pthread_create");
    }

    if(pif != NULL) {
        if (pthread_create(&remote_th, NULL, recv_from_lan, NULL) != 0) {
            perror("pthread_create");
        }
    }

    while (1) {
        sleep(1);
    }

    return 0;
}

int
main(int argc, char **argv)
{
    int opt;
    char *conf_file = NULL;
    char *logfile = NULL;

    while ((opt = getopt(argc, argv, "abc:dhi:l:f:p:P:r:tvxw:W")) != -1) {
        switch (opt) {
            case 'a':
                local_ack = TRUE;
                break;
            case 'b':
                beacon = TRUE;
                break;
            case 'c':
                conf_file = optarg;
                break;
            case 'd':
                daemon_flag = TRUE;
                break;
            case 'f':
                logfile = optarg;
                break;
            case 'h':
                usage();
                return 0;
            case 'i':
                vni = atoi(optarg);
                break;
            case 'l':
                offset_t = atoi(optarg);
                break;
            case 'p':
                pif = optarg;
                break;
            case 'P':
                outer_addr = optarg;
                break;
            case 'r':
                link_rate = atoi(optarg);
                break;
            case 't':
                tslot_emu = TRUE;
                break;
            case 'v':
                verbose = TRUE;
                break;
            case 'x':
                print_pkt = TRUE;
                break;
            case 'w':
                if (in_ifnum == 0) {
                    in_ifhead = (struct iflist *)malloc(sizeof (struct iflist));
                    in_iflist = in_ifhead;
                }
                else {
                    in_iflist->next = (struct iflist *)malloc(sizeof (struct iflist));
                    in_iflist = in_iflist->next;
                }
                strcpy(in_iflist->devname, optarg);
                in_ifnum++;
                break;
            case 'W':
                write_vaddr = 1;
                break;
            default:
                usage();
                return -1;
        }
    }

    if (!logfile && daemon_flag == FALSE) {
        logfd = stdout;
    }
    else if (logfile) {
        logfd = fopen(logfile, "a");
        if (!logfd) {
            fprintf(stderr,  "Cannot open logfile.");
            logfd = stdout;
        }
    }
    else {
        logfd = fopen("/dev/null", "w");
    }

    ofdm_idx = rate2ofdm_idx(link_rate);
    dsss_idx = rate2dsss_idx(link_rate);
    if (ofdm_idx == -1 && dsss_idx == -1) {
        fprintf(logfd, "Invalid Rate: %d\n", link_rate);        
        return -1;
    }
    if (conf_file) {
        in_ifhead = NULL;
        in_ifnum = parse_conf(conf_file);
    }
    if (in_ifnum == 0) {
        usage();
        return -1;
    }
    if (out_port == 0) {
        out_port = GNV_PORT;
    }
    if (daemon_flag == TRUE) {
        if (daemon(0, 0) == 0) {
            return asteroid_loop();
        }
        else {
            perror("daemon");
        }
    }
    else {
        return asteroid_loop();
    }
}
