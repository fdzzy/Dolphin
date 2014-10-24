#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <arpa/inet.h>
#include "pkt_gen.h"

extern void crcInit(void);

/* TODO: CRC is not correct right now */
uint32 cal_crc32(const char* buf, size_t len)
{
    uint32 crc32_table[256];
    int i,j;
    uint32 crc;

    for(i=0 ; i<256 ; i++) {
        crc = i;
        for(j=0 ; j<8 ; j++) {
            if(crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
        crc32_table[i] = crc;
    }

    crc = 0xffffffff;
    for(i=0 ; i<len ; i++) {
        crc = (crc >> 8) ^ crc32_table[(crc & 0xff) ^ buf[i]];
    }

    crc ^= 0xffffffff;
    return crc;
}

/* TODO: CRC is not correct right now */
uint16 cal_crc16(const char *buf, size_t len)
{
    uint16 crc16_table[256];
    int i,j;
    uint16 crc;

    for(i=0 ; i<256 ; i++) {
        crc = i;
        for(j=0 ; j<8 ; j++) {
            if(crc & 0x01) {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
        crc16_table[i] = crc;
    }

    crc = 0x0000;
    for(i=0 ; i<len ; i++) {
        crc = (crc >> 8) ^ crc16_table[(crc & 0xff) ^ buf[i]];
    }
    //crc ^= 0x0000;
    return crc;
} 

void pcap_hdr_init(pcap_hdr_t *pcap)
{
    memset(pcap, 0x00, sizeof(pcap_hdr_t));
    pcap->magic_number = PCAP_MAGIC;
    pcap->version_major = PCAP_VER_MAJOR;
    pcap->version_minor = PCAP_VER_MINOR;   /* version 2.4 */ 
    pcap->snaplen = 0x0000ffff;     /* max length 65535 */
    pcap->network = 0x00000001;     /* LINKTYPE_ETHERNET */ 
}

void pcaprec_hdr_init(pcaprec_hdr_t *rec, pkt_t *pkt)
{
    size_t len;
    int i;

    for(len=0, i=0 ; i<pkt->layer_num ; i++) {
        len += pkt->layers[i]->len;
    }

    memset(rec, 0, sizeof(pcaprec_hdr_t));
    rec->incl_len = len;
    rec->orig_len = len;
}

void hex_dump(const void *mem, int size)
{
    int i;
    unsigned int addr = 0x00000000;
    char *buf = (char*)mem;

    printf("Starting address: %x, size: %d\n", (unsigned int)mem, size);
    printf("%08x: ", addr);
    for(i=0; i<size ; i++) {
        if(i && !(i%16)) {
            addr += 16;
            printf("\n%08x: ", addr);
        }
        printf("%02hhx ", buf[i]);
    }
    printf("\n");
}

/* caller to guarantee that buf can contain 6 bytes */
int get_mac(const char *descr, uint8 *buf)
{
    char *line, *token, *str;
    size_t len = 0;
    ssize_t read;
    int i, value;

    if(buf == NULL)
        return -1;

    if(descr)
        printf("%s", descr);

    if( (read = getline(&line, &len, stdin)) != -1 ) {
        if(line[0] == '\n') {
            for(i=0; i<6 ; i++){
                buf[i] = 0;
            }
        } else {
            for(str=line, i=0; i<6 ; str=NULL, i++) {
                token = strtok(str, ":-"); 
                if(token == NULL) {
                    printf("MAC string parse error\n"); 
                    free(line);
                    return -1;
                }
                sscanf(token, "%x", &value);
                //printf("%d: %s is %d or %x\n", i, token, value, value);
                buf[i] = value;
            }
        }
        free(line);
        return 0;
    } else {
        printf("getline error\n");
        free(line);
        return -1;
    }
}

int get_layer_list_option(layer_gen_t *layer_gen)
{
    int i = 0;
    int first = 1;
    int sel;
    char buf[BUF_LEN];
    char ch;
    
    if(layer_gen == NULL) return -1;

    for(; layer_gen[i].descr != NULL ; i++) {
        printf("[%d] - %s\n", (i+1), layer_gen[i].descr);
    }
    if(i==1) {
        sprintf(buf, "[1]");
    } else {
        sprintf(buf, "[1-%d]", i);
    }
    do {
        ch = '\0';
        if(first) {
            first = 0;
        } else { 
            printf("Invalid input!\n");
        }
        printf("Input selection %s: ", buf);
        scanf("%d", &sel);
        /* catch the trailing return */
        while(ch != '\n')
           scanf("%c", &ch);
    } while( (sel < 1) || (sel > i) );

    return (sel-1);
}

int ether_gen(pkt_t *pkt, int layer)
{
    layer_t *ether;
    ether_hdr_t *ether_hdr;
    layer_gen_t *next_list = ether_next_list;
    int sel;

    printf("Input ethernet header info\n");

    ether = malloc(sizeof(layer_t)); 
    ether->type = LAYER_TYPE_ETHER;
    ether->len = sizeof(ether_hdr_t);
    ether->buf = malloc(sizeof(ether_hdr_t));
    
    ether_hdr = (ether_hdr_t*) ether->buf;
    memset(ether_hdr, 0, sizeof(ether_hdr_t));
    
    get_mac("Destination MAC address[00-00-00-00-00-00]: ", ether_hdr->dst_mac);
    get_mac("Source MAC address[00-00-00-00-00-00]: ", ether_hdr->src_mac);

    //for(i=0; i<6 ; i++) {
    //    printf("%x ", ether_hdr->dst_mac[i]);
    //}
    //printf("\n");

    pkt->layers[layer] = ether; 
    /* Get input from user on which layer goes next */
    sel = get_layer_list_option(next_list); 
    /* Construct next layer header */
    if(next_list[sel].hdr_gen_func(pkt, (layer+1)))
        return -1;

    ether_hdr->ether_type = htons(next_list[sel].next_type); 

    return 0;
}

int vlan_gen(pkt_t *pkt, int layer)
{
    layer_t *vlan;
    vlan_hdr_t *vlan_hdr;
    layer_gen_t *next_list = vlan_next_list;
    int sel, vlan_id;
    char ch = '\0';
         
    printf("Input VLAN header info\n");

    vlan = malloc(sizeof(layer_t)); 
    vlan->type = LAYER_TYPE_VLAN;
    vlan->len = sizeof(vlan_hdr_t);
    vlan->buf = malloc(sizeof(vlan_hdr_t));
    
    vlan_hdr = (vlan_hdr_t*) vlan->buf;
    memset(vlan_hdr, 0, sizeof(vlan_hdr_t));

    while(1) {
        ch = '\0';
        printf("Input VLAN ID [0-4095]: ");
        scanf("%d", &vlan_id);
        /* catch the trailing return */
        while(ch != '\n')
            scanf("%c", &ch);
        if(vlan_id < 0 || vlan_id > 4095) {
            printf("Invalid VLAN ID!\n");
        } else {
            break;
        }
    }

    vlan_hdr->vlan = htons(vlan_id);

    pkt->layers[layer] = vlan;
    /* Get input from user on which layer goes next */
    sel = get_layer_list_option(next_list); 
    /* Construct next layer header */
    if(next_list[sel].hdr_gen_func(pkt, (layer+1)))
        return -1;

    vlan_hdr->ether_type = htons(next_list[sel].next_type); 

    return 0;
}

int get_ipv4(const char *descr, uint32 *ip)
{
    char *line, *token, *str;
    size_t len = 0;
    ssize_t read;
    int i, value;

    if(ip == NULL)
        return -1;
    
again:
    if(descr)
        printf("%s", descr);

    *ip = 0;
    
    if( (read = getline(&line, &len, stdin)) != -1 ) {
        if(line[0] != '\n') {
            for(str=line, i=0; i<4 ; str=NULL, i++) {
                token = strtok(str, "."); 
                if(token == NULL) {
                    printf("IP string parse error\n"); 
                    free(line);
                    return -1;
                }
                value = atoi(token);  
                if(value < 0 || value > 255) {
                    printf("Invalid IPv4 address!\n");
                    goto again;
                }
                *ip <<= 8;
                *ip += value;
            }
        }
        free(line);
        return 0;
    } else {
        printf("getline error\n");
        free(line);
        return -1;
    }
}

int ipv4_gen(pkt_t *pkt, int layer)
{
    layer_t *ip;
    ipv4_hdr_t *ip_hdr;
    layer_gen_t *next_list = ipv4_next_list;
    int sel, i;
    //char ch = '\0';
    uint16 crc;
         
    ip = malloc(sizeof(layer_t)); 
    ip->type = LAYER_TYPE_IPv4;
    ip->len = sizeof(ipv4_hdr_t);
    ip->buf = malloc(sizeof(ipv4_hdr_t));
    
    ip_hdr = (ipv4_hdr_t*) ip->buf;
    memset(ip_hdr, 0, sizeof(ipv4_hdr_t));
    ip_hdr->version_ihl |= 0x04 << 4; /* IP version 4 */
    ip_hdr->version_ihl |= 0x05; /* IP header length */

    get_ipv4("Destination IPv4 address[0.0.0.0]: ", &ip_hdr->dst_ip); 
    get_ipv4("Source IPv4 address[0.0.0.0]: ", &ip_hdr->src_ip); 

    //printf("DBG: dst_ip: %x, src_ip: %x\n", ip_hdr->dst_ip, ip_hdr->src_ip);

    ip_hdr->src_ip = htonl(ip_hdr->src_ip);
    ip_hdr->dst_ip = htonl(ip_hdr->dst_ip);
    ip_hdr->ttl_proto = htons((128 << 8) + 6);
    
    // calculate crc, this should be put at the end of this function
    crc = cal_crc16((const char*)ip_hdr, sizeof(ipv4_hdr_t));
    ip_hdr->crc = crc;

    pkt->layers[layer] = ip;
    /* Get input from user on which layer goes next */
    sel = get_layer_list_option(next_list); 
    /* Construct next layer header */
    if(next_list[sel].hdr_gen_func(pkt, (layer+1)))
        return -1;

    ip_hdr->ttl_proto = htons((128 << 8) + next_list[sel].next_type); 
    for(i=layer ; i<pkt->layer_num ; i++) {
        ip_hdr->length += pkt->layers[i]->len;
    }

    return 0;
}

int get_port(const char *descr, uint16 *port)
{
    int iport;
    char ch;

    if(port == NULL)
        return -1;

    while(1) {
        ch = '\0';
        if(descr)
            printf("%s", descr);

        scanf("%d", &iport);
        /* catch the trailing return */
        while(ch != '\n')
           scanf("%c", &ch);
        if(iport < 0 || iport > 65535) {
            printf("Invalid port!\n");
        } else {
            *port = iport;
            break;
        }
    }
    
    return 0;
}

int tcp_gen(pkt_t *pkt, int layer)
{
    layer_t *tcp;
    tcp_hdr_t *tcp_hdr;
    layer_gen_t *next_list = tcp_next_list;
    int sel;

    tcp = malloc(sizeof(layer_t)); 
    tcp->type = LAYER_TYPE_TCP;
    tcp->len = sizeof(tcp_hdr_t);
    tcp->buf = malloc(sizeof(tcp_hdr_t));
    
    tcp_hdr = (tcp_hdr_t*) tcp->buf;
    //memset(tcp_hdr, 0, sizeof(tcp_hdr_t));
    get_port("Destination TCP port: ", &tcp_hdr->dst_port);
    get_port("Source TCP port: ", &tcp_hdr->src_port);
    tcp_hdr->src_port = htons(tcp_hdr->src_port);
    tcp_hdr->dst_port = htons(tcp_hdr->dst_port);
    tcp_hdr->flag = htons(5 << 12);
    tcp_hdr->window = htons(65535);

    pkt->layers[layer] = tcp;
    /* Get input from user on which layer goes next */
    sel = get_layer_list_option(next_list); 
    /* Construct next layer header */
    if(next_list[sel].hdr_gen_func(pkt, (layer+1)))
        return -1;

    return 0;
}

int udp_gen(pkt_t *pkt, int layer)
{
    layer_t *udp;
    udp_hdr_t *udp_hdr;
    layer_gen_t *next_list = udp_next_list;
    int sel;

    udp = malloc(sizeof(layer_t)); 
    udp->type = LAYER_TYPE_UDP;
    udp->len = sizeof(udp_hdr_t);
    udp->buf = malloc(sizeof(udp_hdr_t));
    
    udp_hdr = (udp_hdr_t*) udp->buf;
    //memset(udp_hdr, 0, sizeof(udp_hdr_t));
    get_port("Destination UDP port: ", &udp_hdr->dst_port);
    get_port("Source UDP port: ", &udp_hdr->src_port);
    udp_hdr->src_port = htons(udp_hdr->src_port);
    udp_hdr->dst_port = htons(udp_hdr->dst_port);

    pkt->layers[layer] = udp;
    /* Get input from user on which layer goes next */
    sel = get_layer_list_option(next_list); 
    /* Construct next layer header */
    if(next_list[sel].hdr_gen_func(pkt, (layer+1)))
        return -1;

    return 0;
}

int payload_gen(pkt_t *pkt, int layer)
{
    layer_t *payload;
    int size;
    char ch;

    while(1) {
        ch = '\0';
        printf("Input payload size[1-%d]: ", MAX_PAYLOAD_SIZE);
        scanf("%d", &size);
        /* catch the trailing return */
        while(ch != '\n')
           scanf("%c", &ch);
        if(size < 1 || size > MAX_PAYLOAD_SIZE) {
            printf("Invalid payload size!\n");
            continue;
        } else {
            break;
        }
    } 

    payload = malloc(sizeof(layer_t)); 
    payload->type = LAYER_TYPE_PAYLOAD;
    payload->len = size;
    payload->buf = malloc(sizeof(size));

    // set 'length' field in UDP header
    if(pkt->layers[layer-1]->type == LAYER_TYPE_UDP) {
        udp_hdr_t *udp_hdr = (udp_hdr_t*)pkt->layers[layer-1]->buf;
        udp_hdr->length = htons(size + sizeof(udp_hdr_t));
    }

    pkt->layers[layer] = payload;
    /* This is important: Last layer should set packet layer number */
    pkt->layer_num = layer + 1; 

    return 0;
}

int write_pkt(const char *fname, pkt_t *pkt)
{
    FILE *fp;
    int i;

    fp = fopen(fname, "wb");
    if(fp == NULL) {
        fprintf(stderr, "Can't open file: %s!\n", fname);
        exit(1);
    }

    pcap_hdr_t header;
    pcap_hdr_init(&header);
    hex_dump(&header, sizeof(header));

    /* write PCAP file header */
    fwrite(&header, sizeof(pcap_hdr_t), 1, fp);

    /* write packet header */
    pcaprec_hdr_t rec_hdr;
    pcaprec_hdr_init(&rec_hdr, pkt);   
    //hex_dump(&rec, sizeof(rec));
    fwrite(&rec_hdr, sizeof(pcaprec_hdr_t), 1, fp);

    /* write packet content */
    for(i=0; i<pkt->layer_num ; i++) {
        fwrite(pkt->layers[i]->buf, pkt->layers[i]->len, 1, fp);
    }

    fclose(fp);

    return 0;
}

void cli()
{
    pkt_t pkt;

    memset(&pkt, 0x00, sizeof(pkt_t));
    ether_gen(&pkt, 0);
    write_pkt("test.pcap", &pkt);
}

int main(int argc, char *argv[])
{
    //printf("%d, %d, %d, %d\n", sizeof(uint64), sizeof(uint32), sizeof(uint16), sizeof(uint8));
    crcInit();

    cli();

    return 0;
}
