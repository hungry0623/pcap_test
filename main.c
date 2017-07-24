#include <pcap.h>
#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6
#define ETHER_HEADER_LEN 14
#define IP_ADDR_LEN 4

/* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
    u_char ip_vhl;		/* version << 4 | header length >> 2 */
    u_char ip_tos;		/* type of service */
    u_short ip_len;		/* total length */
    u_short ip_id;		/* identification */
    u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
    u_char ip_ttl;		/* time to live */
    u_char ip_p;		/* protocol */
    u_short ip_sum;		/* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;	/* source port */
    u_short th_dport;	/* destination port */
    tcp_seq th_seq;		/* sequence number */
    tcp_seq th_ack;		/* acknowledgement number */
    u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;		/* window */
    u_short th_sum;		/* checksum */
    u_short th_urp;		/* urgent pointer */
};

const u_char* ether_header_info(const u_char *packet);
const u_char* ip_header_info(const u_char *packet);
const u_char*  tcp_port(const u_char *packet);
u_short data_size(const struct sniff_ip *ip, const struct sniff_tcp *tcp);
void data_output(u_short size, const u_char *packet);

int main(int argc, char *argv[])
{
    pcap_t *handle;			/* Session handle */
    char *dev;			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;		/* The compiled filter */
    char filter_exp[] = "port 80";	/* The filter expression */
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    struct pcap_pkthdr *header;	/* The header that pcap gives us */
    const u_char *packet;		/* The actual packet */
    const u_char *ETHER_HEADER_P;
    const u_char *IP_HEADER_P;
    const u_char *TCP_HEADER_P;
    const u_char *DATA_P;
    u_short DATA_SIZE;
    int check;

    /* Define the device */
    dev = argv[1];
    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    while(1)
    {
        /* Grab a packet */
        check = pcap_next_ex(handle, &header, &packet);
        ETHER_HEADER_P = packet;

        printf("\n================Packet info================= \n\n");

        /* ETH */
        IP_HEADER_P = ether_header_info(ETHER_HEADER_P);

        /* IP */
        TCP_HEADER_P = ip_header_info(IP_HEADER_P);

        /* TCP */
        DATA_P = tcp_port(TCP_HEADER_P);

        /* DATA */
        DATA_SIZE = data_size(IP_HEADER_P, TCP_HEADER_P);
        data_output(DATA_SIZE, DATA_P);
        printf("\n");

        /* And close the session */
    }
    pcap_close(handle);
    return(0);
}

const u_char* ether_header_info(const u_char *p)
{
    const struct sniff_ethernet *eth;

    eth = (struct sniff_ethernet*)(p);
    if(htons(eth->ether_type) == 0x0800)
    {
        printf("Mac Src = ");
        for(int i = 0; i < ETHER_ADDR_LEN; i++)
        {
            printf("%02x", eth->ether_shost[i]);
            if(i != 5)
            {
                printf(":");
            }
        }
        printf("\n");

        printf("Mac Dst = ");
        for(int i = 0; i < ETHER_ADDR_LEN; i++)
        {
            printf("%02x", eth->ether_dhost[i]);
            if(i != 5)
            {
                printf(":");
            }
        }
        printf("\n");

        p += ETHER_HEADER_LEN;

        return p;
    }
}

const u_char* ip_header_info(const u_char *p)
{
    const struct sniff_ip *ip;

    ip = (struct sniff_ip*)(p);
    char src[16] = {0};
    char dst[16] = {0};

    printf("Ip Src = ");
    inet_ntop(AF_INET,&(ip->ip_src),src,16);
    printf("%s", src);
    printf("\n");


    printf("Ip Dst = ");
    inet_ntop(AF_INET,&(ip->ip_dst),dst,16);
    printf("%s", dst);
    printf("\n");

    p += IP_HL(ip)*4;

    return p;
}

const u_char* tcp_port(const u_char *p)
{
    const struct sniff_tcp *tcp;

    tcp = (struct sniff_tcp*)(p);

    printf("tcp sport = %d\n",ntohs(tcp->th_sport));
    printf("tcp dport = %d\n",ntohs(tcp->th_dport));

    p += TH_OFF(tcp)*4;

    return p;
}

u_short data_size(const struct sniff_ip *ip, const struct sniff_tcp *tcp)
{
    u_short size = 0;

    size = ntohs(ip->ip_len) - (IP_HL(ip)*4) - (TH_OFF(tcp)*4);

    return size;
}

void data_output(u_short size, const u_char *p)
{
    printf("====================data====================\n\n");

    for(u_short i = 0; i < size;i++)
    {
        printf("%c",p[i]);
    }

}
