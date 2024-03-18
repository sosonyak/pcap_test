#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define ETHERTYPE_IP 0x0800
#define ETHER_ADDR_LEN 6
#define LIBNET_LIL_ENDIAN 1 // $ echo -n I | od -to2 | head -n1 | cut -f2 -d" " | cut -c6 -> result: 1(little)
#define IP_SIZE 4
#define MAX_PRINT_NUM 10

struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

struct libnet_ipv4_hdr
{
#if (LIBNET_LIL_ENDIAN)
    u_int8_t ip_hl:4,      /* header length */
        ip_v:4;         /* version */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t ip_v:4,       /* version */
        ip_hl:4;        /* header length */
#endif
    u_int8_t ip_tos;       /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};



struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
#if (LIBNET_LIL_ENDIAN)
    u_int8_t th_x2:4,         /* (unused) */
        th_off:4;        /* data offset */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t th_off:4,        /* data offset */
        th_x2:4;         /* (unused) */
#endif
    u_int8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR
#define TH_CWR    0x80
#endif
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};



void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}


const char* mac_addr(uint8_t* mac){
    char* addr = (char*)malloc(ETHER_ADDR_LEN * 3);
    int size;

    if (addr == NULL) {
        fprintf(stderr, "Mac part: malloc failed\n");
        return NULL;
    }

    size = sprintf(addr, "%02x:", mac[0]);
    for (int i = 1; i < ETHER_ADDR_LEN; i++) {
        if (i != ETHER_ADDR_LEN - 1) {
            size += sprintf(addr + size, "%02x:", mac[i]);
        }
        else {
            sprintf(addr + size, "%02x", mac[i]);
        }
    }    
    return addr;
}


const char* ip_addr(uint32_t ip){
    unsigned char ip_char[IP_SIZE];
    memcpy(ip_char, &ip, sizeof(uint32_t));

    char* addr = (char*)malloc(ETHER_ADDR_LEN * 3);
    int size;

    if (addr == NULL) {
        fprintf(stderr, "IP part: malloc failed\n");
        return NULL;
    }

    size = sprintf(addr, "%d.", ip_char[0]);
    for(int i=1; i<IP_SIZE; i++){
        if(i != IP_SIZE-1){
            size += sprintf(addr+size, "%d.", ip_char[i]);
        }
        else{
            sprintf(addr+size, "%d", ip_char[i]);
        }
    }


    return addr;
}

void payload_printer(u_char* p, int p_size){
    for (int i = 0; i < p_size; i++){
        printf(" %02x", p[i]);
    }
}



int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    int count_num = 0;
    while (true) {
        count_num++;

        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        //printf("%u bytes captured\n", header->caplen);

        struct libnet_ethernet_hdr *eth_hdr = (libnet_ethernet_hdr*)packet;
        struct libnet_ipv4_hdr *ip_hdr = (libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
        struct libnet_tcp_hdr *tcp_hdr =
            (libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr));
        u_char* payload =
                (u_char*)(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + tcp_hdr->th_off*4);

        // printf("TCP CHECKER: %d\n", ip_hdr->ip_p); // tcp: 6, udp: 17
        if (ip_hdr->ip_p != IPPROTO_TCP) continue;

        const char* dst_mac = mac_addr(eth_hdr->ether_dhost);
        const char* src_mac = mac_addr(eth_hdr->ether_shost);

        const char* dst_ip = ip_addr(ip_hdr->ip_dst.s_addr);
        const char* src_ip = ip_addr(ip_hdr->ip_src.s_addr);


        printf("[ NO. %d ]\n", count_num);
        printf("Source MAC: %s, Destination MAC: %s\n", src_mac, dst_mac);
        printf("Source IP = %s, Destination IP = %s\n", src_ip, dst_ip);
        printf("Source Port = %d, Destination Port = %d\n", ntohs(tcp_hdr->th_sport), ntohs(tcp_hdr->th_dport));

        printf("Payload:");
//        printf("total length: %d, ip length: %d, tcp offset: %d\n",
//               ntohs(ip_hdr->ip_len), ip_hdr->ip_hl, tcp_hdr->th_off); // total length means total pcap amount - ether header
//        printf("%ld, %ld, %ld", sizeof(struct libnet_ethernet_hdr), sizeof(struct libnet_ipv4_hdr), sizeof(struct libnet_tcp_hdr)); // 14, 20, 20 // but tcp option

        int payload_size = ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl*4) - (tcp_hdr->th_off*4);  // hl is in 4 byte units, so *4

        if (payload_size > MAX_PRINT_NUM){
            payload_printer(payload, MAX_PRINT_NUM);
        }
        else if (payload_size == 0){
            printf(" No Data");
        }
        else{
            payload_printer(payload, payload_size);
        }
        printf("\t(size: %d)\n", payload_size);


        free((void*)dst_mac);
        free((void*)src_mac);
        free((void*)dst_ip);
        free((void*)src_ip);



    }

    pcap_close(pcap);
}
