#include <stdio.h>
#include <libnet.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>

char * ipToStr(unsigned int ipAddress);
char * macToStr(const unsigned char []);
void packetHandlerFunction(unsigned char * userData, const struct pcap_pkthdr * header, const unsigned char * packet);

int main(int argc, char *argv[])
{
    int check;
	char * deviceName, * errorMessage;
	pcap_t * pcapHandler;	

	deviceName = pcap_lookupdev(errorMessage);
	pcapHandler = pcap_open_live(deviceName, BUFSIZ, 1, 1000, errorMessage);
	check = pcap_loop(pcapHandler, 0, packetHandlerFunction, NULL);
	if ( check == - 1)
	{
		return 0;
	}
}

char * macToStr(const unsigned char mac[6])
{
	static char buf[20];
	sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return buf;
}

char * ipToStr(unsigned int ipAddress)
{
	struct sockaddr_in addr;
	addr.sin_addr.s_addr = ipAddress;
	return inet_ntoa(addr.sin_addr);
}


void packetHandlerFunction(unsigned char * userData, const struct pcap_pkthdr * header, const unsigned char * packet)
{

	const struct libnet_ethernet_hdr * ethernetHeader;
	ethernetHeader = (const struct libnet_ethernet_hdr * )packet;
	printf("src MAC : %s\n", macToStr(ethernetHeader->ether_shost));
	printf("dest MAC : %s\n", macToStr(ethernetHeader->ether_dhost));
	
	if( ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP )
	{
		const struct libnet_ipv4_hdr * ipHeader;
		int ipLen, type;
		ipHeader = (const struct libnet_ipv4_hdr * )(packet + LIBNET_ETH_H);			
		ipLen = ipHeader->ip_hl << 2;
		type  = ipHeader->ip_p;
		

		printf("src IP : %s\n", ipToStr(ipHeader->ip_src.s_addr));
		printf("dest IP : %s\n", ipToStr(ipHeader->ip_dst.s_addr));
		printf("protocol : %x\n", type);
		
		switch (type)
		{
			case 6:
				const struct libnet_tcp_hdr * tcpHeader;
				tcpHeader = (const struct libnet_tcp_hdr *)((unsigned char *)ipHeader + ipLen);
				printf("src port : %d\n", ntohs(tcpHeader->th_sport)); 
				printf("dest port : %d\n", ntohs(tcpHeader->th_dport));
				break;
		}
				
	}


}
