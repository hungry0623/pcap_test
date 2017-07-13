#include <pcap.h>
#include <stdio.h>
struct ether_header
{
	unsigned char ether_smac[6];
	unsigned char ether_dmac[6];
};

int main(int argc, char *argv[])
{
	struct ether_header eth;
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
	int i = 0;

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
	/* Print its eth Dst info*/
	printf("eth Dst = ");

	for(i = 0x0; i < 0x6; i++)
	{
		printf("%x",packet[i]);
		if(i != 0x5)
		{
			printf(":");
		}
		else
		{
			printf("\n");
		}
	}

	/* Print its eth Src info*/
	printf("eth Src = ");

	for(i = 0x6; i < 0xC; i++)
	{
		printf("%x",packet[i]);
		if(i != 0xB)
		{
			printf(":");
		}
		else
		{
			printf("\n");
		}
	}

	/* And close the session */
			
	pcap_close(handle);			
	return(0);
}
