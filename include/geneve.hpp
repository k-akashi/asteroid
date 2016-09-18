#define GENEVE_VER 0
#define GNV_PORT 6081
#define DEFAULT_VNI 5001

// Protocol Type
#define GNV_ETH_BRIDGE 0x6558
#define GNV_WL_BRIDGE 0xff01

#define GNV_HDRLEN 8
#define GNV_OPTLEN 4
#define GNV_MAX_OPTLEN 260

/*
 Geneve Header:
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |        Virtual Network Identifier (VNI)       |    Reserved   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Variable Length Options                    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    ver: 2bit
        current version number is 0.
    opt len: 6bit
        Option field length.
        Expressed in four byte multiples.
        Maximum length is 260
        Start of the payload headers can be found using this offset 
        from the end of the base Geneve header.
    o: 1bit
        OAM frame
    c: 1bit
        Critical option present
    rsvd: 6bit
        Reserved
    protocol type: 16bit
        The type of protocol data unit appearing after the Geneve header
        example: ethernet is 0x6558
    vni: 24bit
        Virtual Network Identifier
    reserved
        Reserved

 Tunnel Options
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Option Class         |      Type     |R|R|R| Length  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Variable Option Data                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    option class: 16bit
        Namaspace for the type field
    type: 8bit
    r: 3bit
        reserved
    length: 5bit
        option length
        Expressed in four byte multiples excluding the option header
        total length between 4 and 128 bytes.
*/

#pragma pack(push, 1)
struct geneve_header {
    uint8_t opt_len:6;
    uint8_t ver:2;

    uint8_t reserved1:6;
    uint8_t critical:1;
    uint8_t oam:1;

    uint16_t proto_type;

    uint8_t vni[3];
    uint8_t reverved2;
} __attribute__((packed));
#pragma pack(pop)

#pragma pack(push, 1)
struct geneve_option {
    uint16_t opt_cls;
    uint8_t  type;

    uint8_t len:5;
    uint8_t reserved:3;
} __attribute__((packed));
#pragma pack(pop)

extern uint8_t *encap_geneve(uint8_t *pkt, uint32_t pkt_len, int32_t vni);
extern uint8_t *gnv_alloc();
extern void gnv_free(uint8_t *pkt);
extern uint8_t *add_gnv_hdr(uint8_t *pkt, uint32_t vni, uint16_t proto_type);
extern int add_gnv_opt(uint8_t *pkt, uint8_t type, uint8_t opt_len, uint8_t *data);
extern int add_gnv_payload(uint8_t *pkt, uint8_t *data, uint32_t len);

extern struct geneve_header *get_gnv_hdr(uint8_t *pkt);
extern struct geneve_option *get_gnv_opt(uint8_t *pkt);
extern uint32_t get_gnv_vni(struct geneve_header *gnv_hdr);
extern uint8_t *get_gnv_payload(uint8_t *pkt);
