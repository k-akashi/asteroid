#ifndef __HWSIM_MMAP_H__
#define __HWSIM_MMAP_H__

#define PAGE_COUNT 64
#define MAX_SIZE (PAGE_SIZE * PAGE_COUNT)
#define MMAP_DEVNAME "hwsim_mmap"
#define CLASS_NAME "hwsim_mmap"

#define IOCREGMEM _IO('i', 1)
#define IOCUNREGMEM _IO('i', 2)

static int hwsim_mmap_enabled = 0;

struct hwsim_tx_rate_flag {
    signed char idx;
    uint16_t flags;
} __attribute__((__packed__));

struct hwsim_mmap_header {
    u8 transmitter[6];
    u16 flags;
    u32 freq;
    u64 cookie;
    struct hwsim_tx_rate tx_attempts[IEEE80211_TX_MAX_RATES];
    struct hwsim_tx_rate_flag tx_attempts_flags[IEEE80211_TX_MAX_RATES];
}; // __attribute__((__packed__));

#define PAGE_SIZE 4096
#define DATA_SIZE PAGE_SIZE - sizeof (struct hwsim_mmap_header) - (sizeof (u16) * 2) - sizeof (struct hwsim_mmap_header) - sizeof (struct mmap_mbuf *) - sizeof (struct mmap_mbuf *)
struct mmap_mbuf;
struct mmap_mbuf {
    u16 id;
    u16 len;
    struct hwsim_mmap_header hdr;
    struct mmap_mbuf *prev;
    struct mmap_mbuf *next;
    uint8_t data[DATA_SIZE];
}; // __attribute__((__packed__));

struct mmap_container {
    u64 frame_count;
    struct mmap_mbuf *head;
    struct mmap_mbuf *tail;
};
struct mmap_container mbuf_c;

//struct hwsim_mmap_priv {
//    wait_queue_head_t wq;
//    unsigned int num_pages;
//    struct mmap_mbuf *head;
//    struct mmap_mbuf *tail;
//    char **page_ptr;
//};
//struct hwsim_mmap_priv *mmap_priv = NULL;

struct shared_struct {
    unsigned long len;
    unsigned long off;
};

#endif // __HWSIM_MMAP_H__


