#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <signal.h>
#include "listLib.h"

void printStatistics(int numberOfNetFlow, int numberOfTcpNetFlow,
					 int numberOfUdpNetFlow, int totalPackets, int totalUDP, int totalTCP, int totalTCPbytes, int totalUDPbytes);

struct detailsForPrintStruct
{
	uint32_t seq_number;
	int totalPackets;
	struct Node *head; //= NULL;
	char deviceMAC[18];
	int totalTCP;
	int totalUDP;
	int totalTCPbytes;
	int totalUDPbytes;
	int totalNetFlow;
	int totalTCPFlow;
	int totalUDPFlow;
};
struct detailsForPrintStruct *detailsForPrint = NULL; //Global,because we need it,to print it if ctrl + c is pressed.
pcap_t *handle;										  //Global,so we can close it after the interupt signal.

void INThandler(int dummy) //Call this function when ctrl + c is pressed.
{
	int totalNetFlow = getTotalNetFlow(detailsForPrint->head);
	int totalTCPFlow = getTcpNetFlow(detailsForPrint->head);
	int totalUDPFlow = getUDPNetFlow(detailsForPrint->head);
	printStatistics(totalNetFlow, totalTCPFlow, totalUDPFlow, detailsForPrint->totalPackets, detailsForPrint->totalUDP, detailsForPrint->totalTCP, detailsForPrint->totalTCPbytes, detailsForPrint->totalUDPbytes);
	pcap_close(handle);
	free(detailsForPrint);
	exit(0);
}

void printPacketInfo(char *sourceIp, char *destIp, int sourcePort, int destPort, char *tcp_or_udp,
					 int ipver, int tcp_udp_headerlen, int payloadLen, int retransmited) //Prints  packet's info.
{
	printf("---------Packet----------\n");
	printf("Ip protocol version: Ipv%d\n", ipver);
	printf("4th Layer version: %s\n", tcp_or_udp);
	printf("Source IP: %s\n", sourceIp);
	printf("Destination IP: %s\n", destIp);
	printf("%s Header length is %d bytes.\n", tcp_or_udp, tcp_udp_headerlen);
	printf("Payload length is %d bytes.\n", payloadLen);
	printf("Source port is %d\n", sourcePort);
	printf("Destination port is %d\n", destPort);
	if (retransmited == 1)
	{
		printf("Retransmitted Packet.\n");
	}
}

void printStatistics(int numberOfNetFlow, int numberOfTcpNetFlow, int numberOfUdpNetFlow,
					 int totalPackets, int totalUDP, int totalTCP, int totalTCPbytes, int totalUDPbytes) //Print the final statistics.
{
	printf("\n--- Captured Packets Statistics ---\n");
	printf("Total number of network flows captured: %d\n", numberOfNetFlow);
	printf("Number of TCP network flows captured: %d\n", numberOfTcpNetFlow);
	printf("Number of UDP network flows captured: %d\n", numberOfUdpNetFlow);
	printf("Total number of packets received: %d\n", totalPackets);
	printf("Total number of TCP packets received: %d\n", totalTCP);
	printf("Total number of UDP packets received: %d\n", totalUDP);
	printf("Total bytes of TCP packets received: %d\n", totalTCPbytes);
	printf("Total bytes of UDP packets received: %d\n", totalUDPbytes);
}

void printNotAcceptedPacket() //Not tcp/udp ip4/ip6
{
	printf("---------Packet----------\n");
	printf("Not accepted packet,skipping...\n");
}

void packet_handler(u_char *detailsForPrintArgs, const struct pcap_pkthdr *header, const u_char *packet) //being called,everytime a packet found.
{
	detailsForPrint->totalPackets++; //Add one packet to total packets.
	struct ether_header *eth_header;

	//Initialize headers structs.
	struct ip *ip4_header;
	struct ipv6
	{
		unsigned int
			version : 4,
			traffic_class : 8,
			flow_label : 20;
		uint16_t length;
		uint8_t next_header;
		uint8_t hop_limit;
		struct in6_addr src;
		struct in6_addr dst;
	};
	struct ipv6 *ipv6_header;
	struct tcphdr *tcp_header;

	eth_header = (struct ether_header *)packet; //First header is the ethernet header.
	//printf("Dest MAC: %d\n", ntohs(eth_header->ether_dhost));

	//Get packet's Destination MAC adress.
	char packetDestinationMac[18];
	strcpy(packetDestinationMac, "");
	sprintf(packetDestinationMac, "%02x:%02x:%02x:%02x:%02x:%02x",
			(unsigned)eth_header->ether_dhost[0],
			(unsigned)eth_header->ether_dhost[1],
			(unsigned)eth_header->ether_dhost[2],
			(unsigned)eth_header->ether_dhost[3],
			(unsigned)eth_header->ether_dhost[4],
			(unsigned)eth_header->ether_dhost[5]);
	packetDestinationMac[18] = '\0';

	int ethernet_header_length = 14; //fixed
	int ip_header_length;
	int tcp_header_length;
	char tcp_or_udp[4];
	char destIp[30];
	char srcIp[30];
	int payload_length;
	int tcp_or_udp_headerLen;
	int srcPort;
	int dstPort;
	int retrans = 0;
	int valid = 0; //TCP/UDP AN ip4/ip6 are valid options for this project.
	int protocol_code = 0;

	//Check ipv6 or ipv4
	if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) //Ipv4
	{
		ip4_header = (struct ip *)(packet + sizeof(struct ether_header));						  //Second header is ip header.
		tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip)); //Third header is ip header.
		ip_header_length = 4 * (ip4_header->ip_hl);

		int tcp_or_udp_packet_length = ntohs(ip4_header->ip_len) - ip_header_length;

		//***********INTERNAL PROTOCOLS CODE******************
		//protocol = 10 means UDP and ip4
		//protocol = 11 means TCP and ip4
		//protocol = 21 means UDP and ip6
		//protocol = 22 means TCP and ip6

		//We didnt allocate a udp struct,because we only need sport and dport.These two values are in the same positions with tcp struct(udp size is fixed).
		//Check protocol.
		if ((ip4_header->ip_p) == 17) //UDP
		{
			detailsForPrint->totalUDPbytes += tcp_or_udp_packet_length; //Add packet's udp bytes to total udp bytes.
			detailsForPrint->totalUDP++;								//Increase total Udp packets by 1.
			protocol_code = 10;
			strcpy(tcp_or_udp, "UDP");
			tcp_or_udp_headerLen = 8; //fixed
			valid = 1;
		}
		else if ((ip4_header->ip_p) == 6) //TCP
		{
			detailsForPrint->totalTCP++;
			detailsForPrint->totalTCPbytes += tcp_or_udp_packet_length;
			protocol_code = 11;
			strcpy(tcp_or_udp, "TCP");
			tcp_or_udp_headerLen = 4 * (tcp_header->th_off);
			valid = 1;

			//If the packet is incoming
			if ((strcmp(packetDestinationMac, detailsForPrint->deviceMAC)) == 0)
			{
				//Check if the packet is retransmited by comparing dequences numbers.
				if (ntohl(tcp_header->th_seq) >= detailsForPrint->seq_number)
				{
					detailsForPrint->seq_number = ntohl(tcp_header->th_seq);
				}
				else
				{
					retrans = 1;
				}
			}
		}

		if (valid == 1) //TCP or UDP nd ip4
		{
			payload_length = (tcp_or_udp_packet_length - tcp_or_udp_headerLen); //Calculate payload length.
			strcpy(destIp, inet_ntoa(ip4_header->ip_src));
			strcpy(srcIp, inet_ntoa(ip4_header->ip_dst));
			srcPort = ntohs(tcp_header->th_sport);
			dstPort = ntohs(tcp_header->th_dport);
			printPacketInfo(srcIp, destIp, srcPort, dstPort, tcp_or_udp, 4, tcp_or_udp_headerLen, payload_length, retrans); //Print packet's info.
		}
		else //not accepted packet
		{
			printNotAcceptedPacket();
		}
	}
	else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6) //Ipv6
	{
		ipv6_header = (struct ipv6 *)(packet + sizeof(struct ether_header));
		tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ipv6));

		int tcp_or_udp_packet_length = ipv6_header->length;
		if ((ipv6_header->next_header) == 17) //UDP
		{
			detailsForPrint->totalUDPbytes += tcp_or_udp_packet_length;
			detailsForPrint->totalUDP++;
			protocol_code = 21;
			strcpy(tcp_or_udp, "UDP");
			tcp_or_udp_headerLen = 8; //fixed
			valid = 1;
		}
		else if ((ipv6_header->next_header) == 6) //TCP
		{
			detailsForPrint->totalTCPbytes += tcp_or_udp_packet_length;
			detailsForPrint->totalTCP++;
			protocol_code = 22;
			strcpy(tcp_or_udp, "TCP");
			tcp_or_udp_headerLen = 4 * (tcp_header->th_off);

			valid = 1;

			//If the packet is incoming
			if ((strcmp(packetDestinationMac, detailsForPrint->deviceMAC)) == 0)
			{
				//Check if packet is retransmited
				if (ntohl(tcp_header->th_seq) >= detailsForPrint->seq_number)
				{
					detailsForPrint->seq_number = ntohl(tcp_header->th_seq);
				}
				else
				{
					retrans = 1;
				}
			}
		}

		if (valid == 1)
		{
			payload_length = (tcp_or_udp_packet_length - tcp_or_udp_headerLen);
			char srcAddr[INET6_ADDRSTRLEN];
			char dstAddr[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &ipv6_header->src, srcAddr, INET6_ADDRSTRLEN);
			inet_ntop(AF_INET6, &ipv6_header->dst, dstAddr, INET6_ADDRSTRLEN);
			strcpy(destIp, dstAddr);
			strcpy(srcIp, srcAddr);
			srcPort = ntohs(tcp_header->th_sport);
			dstPort = ntohs(tcp_header->th_dport);
			printPacketInfo(srcIp, destIp, srcPort, dstPort, tcp_or_udp, 6, tcp_or_udp_headerLen, payload_length, retrans);
		}
		else
		{
			printNotAcceptedPacket();
		}
	}
	else //Not ipv4 or ipv6.
	{
		printNotAcceptedPacket();
	}

	if (valid == 1) //if valid,check if it exists in a net_flow.If it isnt exist,create a new net_flow.
	{
		if (search(detailsForPrint->head, srcIp, destIp, srcPort, dstPort, protocol_code) == false)
		{
			push(&(detailsForPrint->head), srcIp, destIp, srcPort, dstPort, protocol_code);
		}

		//printInfoNode(head);
	}
}

void usage(void)
{
	printf(
		"\n"
		"usage:\n"
		"\t./tool \n"
		"Options:\n"
		"-i Network interface name (e.g., eth0)\n"
		"-r Packet capture file name (e.g. test.pcap)\n"
		"-h, Help message\n\n");

	exit(1);
}

//Returns Device Mac Adress
char *
getDeviceMacAdress(char *device)
{
	char command[128];
	char macAdress[18];
	snprintf(command, sizeof(command), "cat /sys/class/net/%s/address",
			 device);
	FILE *fd = popen(command, "r");
	if (fd == NULL)
	{
		fprintf(stderr, "Could not open pipe,Retransmisions flags will be incorrect.\n");
	}
	// Read process output
	char *buffer = malloc(sizeof(char) * 18);
	fgets(buffer, 18, fd);

	return buffer;
}

void monitor_interface(const char *dev_name)
{
	char error_buffer[PCAP_ERRBUF_SIZE];
	char *macAdress;
	macAdress = getDeviceMacAdress((char *)dev_name);
	int snapshot_len = 1028;
	int promiscuous = 0;
	int timeout = 1000;

	//Initialize details struct,that they will be printed at the exit.
	detailsForPrint =
		(struct detailsForPrintStruct *)malloc(sizeof(struct detailsForPrintStruct));
	detailsForPrint->seq_number = 0;
	detailsForPrint->totalPackets = 0;
	detailsForPrint->totalUDP = 0;
	detailsForPrint->totalTCP = 0;
	detailsForPrint->totalTCPbytes = 0;
	detailsForPrint->totalUDPbytes = 0;
	strcpy(detailsForPrint->deviceMAC, macAdress);

	//Check if the user's input device exists.
	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	int check_device = pcap_lookupnet(dev_name, &netp, &maskp, error_buffer);
	if (check_device == -1)
	{
		printf("%s\n", error_buffer);
		exit(0);
	}
	handle = pcap_open_live(dev_name, snapshot_len, promiscuous, timeout, error_buffer);
	printf("Press ctrl + C,to stop the capture.\n");
	pcap_loop(handle, 0, packet_handler, (u_char *)detailsForPrint);
}

void monitor_fileName(char *file_name)
{
	char error_buffer[PCAP_ERRBUF_SIZE];
	//Initialize
	detailsForPrint =
		(struct detailsForPrintStruct *)malloc(sizeof(struct detailsForPrintStruct));
	detailsForPrint->seq_number = 0;
	detailsForPrint->totalPackets = 0;
	detailsForPrint->totalUDP = 0;
	detailsForPrint->totalTCP = 0;
	detailsForPrint->totalTCPbytes = 0;
	detailsForPrint->totalUDPbytes = 0;

	handle = pcap_open_offline(file_name, error_buffer);
	if (handle == NULL)
	{
		fprintf(stderr, "pcap_open_offline failed: %s\n", error_buffer);
		exit(EXIT_FAILURE);
	}

	pcap_loop(handle, 0, packet_handler, NULL);
	INThandler(0);
}

int main(int argc, char *argv[])
{
	signal(SIGINT, INThandler);
	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	while ((ch = getopt(argc, argv, "i:r:")) != -1)
	{
		switch (ch)
		{
		case 'i':
			monitor_interface(optarg);
			break;
		case 'r':
			monitor_fileName(optarg);
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	return 0;
}