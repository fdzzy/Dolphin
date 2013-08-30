#ifndef __DOLPHIN_PKT_GEN_H__
#define __DOLPHIN_PKT_GEN_H__

typedef unsigned long long uint64;
typedef unsigned int uint32;
typedef unsigned short uint16;
typedef unsigned char uint8; 
typedef long long int64;
typedef int int32;
typedef short int16;
typedef char int8; 

#define packed __attribute__ ((__packed__))

#define PCAP_MAGIC      0xa1b2c3d4
#define PCAP_VER_MAJOR  0x0002
#define PCAP_VER_MINOR  0x0004
#define MAX_LAYERS 20
#define BUF_LEN 512 
#define MAX_PAYLOAD_SIZE 500

typedef struct packed pcap_hdr_s {
    uint32  magic_number;   /* magic number */
    uint16  version_major;  /* major version number */
    uint16  version_minor;  /* minor version number */
    int32   thiszone;       /* GMT to local correction */
    uint32  sigfigs;        /* accuracy of timestamps */ 
    uint32  snaplen;        /* max length of captured packets, in octets */
    uint32  network;        /* data link type */
} pcap_hdr_t;

typedef struct packed pcaprec_hdr_s {
    uint32  ts_sec;         /* timestamp seconds */
    uint32  ts_usec;        /* timestamp microseconds */
    uint32  incl_len;       /* number of octets of packet saved in file */
    uint32  orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

/*typedef struct pcap_s {
    pcap_hdr_t  pcap_header;
    pcaprec_t   *pkt;
} pcap_t;*/

#define ETHER_TYPE_IPv4 0x0800
#define ETHER_TYPE_ARP  0x0806
#define ETHER_TYPE_IPv6 0x86DD
#define ETHER_TYPE_VLAN 0x8100
#define ETHER_TYPE_QinQ 0x9100

typedef struct packed ether_hdr_s {
    uint8   dst_mac[6];
    uint8   src_mac[6];
    uint16  ether_type; 
} ether_hdr_t;

typedef struct packed vlan_hdr_s {
    uint16  vlan; 
    uint16  ether_type;
} vlan_hdr_t;

typedef struct packed ipv4_hdr_s {
    uint8   version_ihl;
    uint8   dscp_ecn;
    uint16  length;
    uint16  id;
    uint16  flags_frag;
    uint16  ttl_proto;
    uint16  crc;
    uint32  src_ip;
    uint32  dst_ip;
} ipv4_hdr_t;

typedef struct packed ipv6_hdr_s {
    uint32  vcf;    /* version, traffic class, flow label */
    uint16  len;    /* payload length */
    uint8   next_hdr;   /* next header type */
    uint8   hop;    /* hop limit */
    uint8   src[16];
    uint8   dst[16];
} ipv6_hdr_t;

typedef struct packed tcp_hdr_s {
    uint16  src_port;
    uint16  dst_port;
    uint32  seq;
    uint32  ack;
    uint16  flag;
    uint16  window;
    uint16  checksum;
    uint16  urgent;
} tcp_hdr_t;

int header_len[] = {
    sizeof(ether_hdr_t),
    sizeof(vlan_hdr_t),
    sizeof(ipv4_hdr_t),
    sizeof(tcp_hdr_t)
};

typedef enum layer_type_e {
    LAYER_TYPE_ETHER = 0,
    LAYER_TYPE_VLAN,
    LAYER_TYPE_IPv4,
    LAYER_TYPE_TCP,
    LAYER_TYPE_UDP,
    LAYER_TYPE_PAYLOAD
} layer_type_t;

typedef struct layer_s {
    layer_type_t type;
    void   *buf;    // The buffer to store the actual header
    size_t  len;    // The size of the header buffer
} layer_t;

typedef struct packed pkt_s {
    layer_t *layers[MAX_LAYERS];
    int     layer_num;  // Last layer should set this number
} pkt_t;

typedef struct pcaprec_s {
    pcaprec_hdr_t rec_header;
    pkt_t *pkt;
} pcaprec_t;

typedef struct layer_gen_s {
    char *descr;
    uint16 next_type;
    int (*hdr_gen_func)(pkt_t*, int);
    struct layer_gen_s *next_layers;
} layer_gen_t;

int ether_gen(pkt_t*, int);
int vlan_gen(pkt_t*, int);
int ipv4_gen(pkt_t*, int);
int tcp_gen(pkt_t*, int);
int udp_gen(pkt_t*, int);
int payload_gen(pkt_t*, int);

layer_gen_t payload_next_list[] =
{
    {
        NULL
    }
};

layer_gen_t tcp_next_list[] =
{
    {
        "PAYLOAD",
        0,
        payload_gen,
        payload_next_list
    },
    {
        NULL
    }
};

layer_gen_t udp_next_list[] =
{
    {
        "PAYLOAD",
        0,
        payload_gen,
        payload_next_list
    },
    {
        NULL
    }
};

layer_gen_t ipv4_next_list[] =
{
    {
        "TCP",
        6,
        tcp_gen,
        tcp_next_list
    },
    {
        "UDP",
        17,
        udp_gen,
        udp_next_list
    },
    {
        NULL
    }
}; 

layer_gen_t vlan_next_list[] =
{
    {
        "IPv4",
        ETHER_TYPE_IPv4, 
        ipv4_gen,
        ipv4_next_list
    },
    {
        NULL
    }
};

layer_gen_t ether_next_list[] =
{
    {
        "VLAN",
        ETHER_TYPE_VLAN,
        vlan_gen,
        vlan_next_list
    },
    {
        "IPv4",
        ETHER_TYPE_IPv4,
        ipv4_gen,
        ipv4_next_list
    },
    {
        NULL
    }
};

layer_gen_t pkt_start[] =
{
    {
        "ETHERNET",
        0,
        ether_gen,
        ether_next_list
    },
    {
        NULL
    }
};

#endif
