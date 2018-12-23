#define FALSE   0
#define TRUE    1

#define HWSIM_TX_CTL_REQ_TX_STATUS  1
#define HWSIM_TX_CTL_NO_ACK         (1 << 1)
#define HWSIM_TX_STAT_ACK           (1 << 2)

#define HWSIM_CMD_REGISTER          1
#define HWSIM_CMD_FRAME             2
#define HWSIM_CMD_TX_INFO_FRAME     3

#define HWSIM_ATTR_ADDR_RECEIVER    1
#define HWSIM_ATTR_ADDR_TRANSMITTER 2
#define HWSIM_ATTR_FRAME            3
#define HWSIM_ATTR_FLAGS            4
#define HWSIM_ATTR_RX_RATE          5
#define HWSIM_ATTR_SIGNAL           6
#define HWSIM_ATTR_TX_INFO          7
#define HWSIM_ATTR_COOKIE           8
#define HWSIM_ATTR_MAX              8

#define IEEE80211_TX_MAX_RATES      4

#define VERSION_NR 1

#define IEEE80211_MAX_RATES_PER_TX  5
#define IEEE80211_AVAILABLE_RATES   12

#define ETH_ALEN    6

#define MAX_POOL    4096
#define MAX_BUF     2048

#define TX      1
#define TX_ACK  2

#define PLCP_11B    1
#define PLCP_11G    2
#define PLCP_11A    2

#define PLCP_PREAMBLE_11A   12 // us

// A slot time
#define T_SLOT_11B      20  // us
#define T_SLOT_11A      9   // us

// Short inter-frame space time
#define T_SIFS_11A      16  // us
#define T_SIFS_11B      10  // us

// Distributed inter-frame space time
#define T_DIFS_11A      34  // us
#define T_DIFS_11B      50  // us

// Minimum backoff Window size
#define CW_MIN_11A      16
#define CW_MIN_11B      31

// Average backoff Window size
#define CW_AVERAGE_11A  (CW_MIN_11A * T_SLOT_11A) / 2
#define CW_AVERAGE_11B  (CW_MIN_11B * T_SLOT_11B) / 2

// MAC overhead bytes
#define L_H_DATA        28

// ACK size
#define L_ACK           14

// Transmission time os MAC overhead
#define T_H_DATA        0 // ???

// Propagation delay
#define P_11A         1   // us
#define P_11B         1   // us

// Transmission time of the physical preamble
#define T_P_11A         16  // us
#define T_P_11B         144 // us

// Transmission time of the PHY header
#define T_PHY_11A       4   // us
#define T_PHY_11B       48  // us

#define MAC_HDR_LEN     26
#define MAC_FCS_LEN     4
#define MAC_LLC_LEN     8

static const uint32_t plcp_tb[] = {
    192000, // 11b
    20000,  // 11a
    0       // test
};

struct radiotap_hdr {
    uint8_t  rev;
    uint8_t  pad;
    uint16_t len;
    uint32_t present;
    uint64_t tstamp;
    uint8_t  flags;
    uint8_t  rate;
    uint16_t freq;
    uint16_t cflags;
};

struct wlan_macaddr {
    unsigned char addr[6];
};

struct hwsim_tx_rate {
    int8_t idx;
    uint8_t count;
    unsigned char pad[2];
};

struct packed_data {
    int32_t type; 
    struct wlan_macaddr src;
    struct wlan_macaddr tx;
    unsigned char pad[2];
    uint32_t flags;
    struct hwsim_tx_rate tx_rates;
    uint64_t cookie;
    int32_t seq;
    //uint32_t len;
    //char data[2048];
};

struct hwsim_frame {
    // Frame information
    int flags;
    int signal;
    uint32_t freq;
    uint64_t cookie;

    int tx_rate_cnt;
    struct hwsim_tx_rate tx_rates[IEEE80211_TX_MAX_RATES];

    // station, phy address
    uint8_t *phyaddr;
    uint8_t *wlanaddr;

    ssize_t data_len;
    uint8_t *data;
};
