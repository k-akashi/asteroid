#include <arpa/inet.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "geneve.hpp"

uint8_t *gnv_alloc()
{
    uint8_t *pkt;

    //pkt = (uint8_t *)malloc(pkt_len + geneve_len);
    pkt = (uint8_t *)malloc(9000);
    memset(pkt, 0, 9000);

    return pkt;
}

void gnv_free(uint8_t *pkt)
{
    free(pkt);
}

uint8_t * add_gnv_hdr(uint8_t *pkt, uint32_t vni, uint16_t proto_type)
{
    struct geneve_header gnv_hdr;

    memset(&gnv_hdr, 0, sizeof (struct geneve_header));
    gnv_hdr.ver            = GENEVE_VER;
    gnv_hdr.opt_len        = 0;
    gnv_hdr.critical       = 0;
    gnv_hdr.oam            = 0;
    gnv_hdr.proto_type     = htons(proto_type);
    gnv_hdr.vni[0]         = (vni & 0x000ff0000) >> 16;
    gnv_hdr.vni[1]         = (vni & 0x00000ff00) >> 8;
    gnv_hdr.vni[2]         = (vni & 0x0000000ff);
    gnv_hdr.reverved2      = 0;

    memcpy((void *)pkt, (void *)&gnv_hdr, GNV_HDRLEN);

    return pkt;
}

int add_gnv_opt(uint8_t *pkt, uint8_t type, uint8_t opt_len, uint8_t *opt)
{
    struct geneve_header *gnv_hdr;
    struct geneve_option *gnv_opt;

    if (opt_len > 120) {
        printf("option length: %u > 120\n", opt_len);
        return -1;
    }
    gnv_hdr = (struct geneve_header *)pkt;
    gnv_opt = (struct geneve_option *)(pkt + GNV_HDRLEN + (gnv_hdr->opt_len * 4));

    if ((gnv_hdr->opt_len * 4) + GNV_OPTLEN + opt_len > GNV_MAX_OPTLEN) {
        printf("Cannot add geneve option\n");
        return -1;
    }

    gnv_hdr->opt_len += (GNV_OPTLEN + opt_len) / 4;

    gnv_opt->opt_cls  = 0;
    gnv_opt->type     = type;
    gnv_opt->len      = opt_len;
    gnv_opt->reserved = 0;
    memcpy(gnv_opt + 1, opt, opt_len);

    return GNV_HDRLEN + (gnv_hdr->opt_len * 4);
}

int add_gnv_payload(uint8_t *pkt, uint8_t *data, uint32_t len)
{
    struct geneve_header *gnv_hdr;

    gnv_hdr = (struct geneve_header *)pkt;
    memcpy(pkt + GNV_HDRLEN + (gnv_hdr->opt_len * 4), data, len);

    return GNV_HDRLEN + (gnv_hdr->opt_len * 4) + len;
}

struct geneve_option *get_gnv_opt(uint8_t *pkt)
{
    struct geneve_option *gnv_opt;

    gnv_opt = (struct geneve_option *)(pkt + GNV_HDRLEN);

    return gnv_opt;
}

uint32_t get_gnv_vni(struct geneve_header *gnv_hdr)
{
    uint32_t vni;
    vni = (gnv_hdr->vni[0] << 16) + (gnv_hdr->vni[1] << 8) + (gnv_hdr->vni[2]);

    return vni;
}

uint8_t *get_gnv_payload(uint8_t *pkt)
{
    uint8_t *data;
    struct geneve_header *gnv_hdr;

    gnv_hdr = (struct geneve_header *)pkt;
    data = pkt + sizeof (struct geneve_header) + (gnv_hdr->opt_len * 4);

    return data;
}

uint8_t *encap_geneve(uint8_t *pkt, uint32_t pkt_len, int32_t vni)
{
    uint8_t *epkt;
    int geneve_len;
    struct geneve_header ghdr;

    memset(&ghdr, 0, sizeof (struct geneve_header));
    ghdr.ver            = GENEVE_VER;
    ghdr.opt_len        = 0;
    ghdr.critical       = 0;
    ghdr.oam            = 0;
    ghdr.proto_type     = htons(GNV_ETH_BRIDGE);
    ghdr.vni[0]         = (vni & 0x000ff0000) >> 16;
    ghdr.vni[1]         = (vni & 0x00000ff00) >> 8;
    ghdr.vni[2]         = (vni & 0x0000000ff);
    ghdr.reverved2      = 0;

    geneve_len = sizeof (struct geneve_header);
    epkt = (uint8_t *)malloc(pkt_len + geneve_len);

    memcpy((void *)epkt, (void *)&ghdr, geneve_len);
    memcpy((void *)(epkt + geneve_len), (void *)pkt, geneve_len);

    return epkt;
}
