#include <pcap.h>
#include <stdio.h>

#define MAC_NUM 0x6
#define IP_NUM 0x1a
#define TCP_NUM 0x22
#define DATA_BYTES 100

void ether_mac(const u_char *packet);
void ip_ip(const u_char *packet);
void tcp_port(const u_char *packet);
void data_output(const u_char *packet);

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
	int check;
	
	/* Define the device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
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
	/* Grab a packet */
	check = pcap_next_ex(handle, &header, &packet);
	printf("\n================Packet info================= \n\n");
	/* Print its ETHER_MAC info*/
	ether_mac(packet);
	/* Print its IP_IP info*/
	ip_ip(packet);
	/* Print its TCP_PORT info*/
	tcp_port(packet);
	/* Print its DATA_OUTPUT info*/
	data_output(packet);
	printf("\n");
	/* And close the session */
			
	pcap_close(handle);			
	return(0);
}

void ether_mac(const u_char *packet)
{
	int i = 0;

	printf("eth Src = ");

	for(i = MAC_NUM; i < (MAC_NUM*2); i++)
	{
		printf("%02x",packet[i]);

		if(i != ((MAC_NUM*2)-1))
		{
			printf(":");
		}
		else
		{
			printf("\n");
		}
	}

	printf("eth Dst = ");

	for(i = 0x0; i < MAC_NUM; i++)
	{
		printf("%02x",packet[i]);

		if(i != 0x5)
		{
			printf(":");
		}
		else
		{
			printf("\n");
		}
	}

	

}

void ip_ip(const u_char *packet)
{
	int i = 0;
	
	printf("ip Src = ");

	for(i = IP_NUM; i < IP_NUM+4; i++)
	{
		printf("%d",packet[i]);

		if(i != (IP_NUM+3))
		{
			printf(".");
		}
		else
		{
			printf("\n");
		}
	}

	printf("ip Dst = ");

	for(i = IP_NUM+4; i < IP_NUM+8; i++)
	{
		printf("%d",packet[i]);

		if(i != (IP_NUM+7))
		{
			printf(".");
		}
		else
		{
			printf("\n");
		}
	}

}

void tcp_port(const u_char *packet)
{
	printf("Src Port = %d \n", (packet[TCP_NUM]*0x100) + packet[TCP_NUM+1]);
	printf("Dst Port = %d \n", (packet[TCP_NUM+2]*0x100) + packet[TCP_NUM+3]);
}

void data_output(const u_char *packet)
{
	int i = 0;
	printf("\n====================DATA==================== \n");
	for(i = 0; i < DATA_BYTES; i++)
	{
		if(i % 16 == 0)
		{
			printf("\n");
		}
		else
		{
			printf("%02x ",packet[i]);
		}
	}
}
