/*
 ============================================================================
 Name        : mydump.c
 Author      : iti
 Version     :
 Copyright   : Your copyright notice
 Description : my tcpdump
 ============================================================================
 */

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <time.h>

#include "structures.h"

#define SIZE_ETHERNET 14
struct sniff_ethernet *ethernet; /* The ethernet header */
struct sniff_ip *ip; /* The IP header */
struct sniff_tcp *tcp; /* The TCP header */
struct sniff_udphdr *udp;
struct sniff_icmphdr* icmp;
char *payload; /* Packet payload */

pkt_data_t pdt = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, NULL, NULL };

u_int size_ip;
u_int size_packet;

//print last line of payload which will be less than 16 bytes.
void printLastLine(u_char* payload, int size, char* payloadNew,
		char* totalPayload) {
	char buf[size];
	char buf2[size];
	u_char* data = payload;
	int rem_size;
	int k = 0;
	for (k = 0; k < size; k++) {
		sprintf(buf, "%02x ", *data);
		strcat(totalPayload, buf);
		data++;
	}
	rem_size = 16 - size;
	int j = 0;
	for (j = 0; j < 3 * rem_size; j++) {
		strcat(totalPayload, " ");
	}
	int l = 0;
	//fprintf(stdout, "  ");
	strcat(totalPayload, "  ");
	data = payload;
	for (l = 0; l < size; l++) {
		if (isprint(*data)) {
			sprintf(buf2, "%c", *data);
			strcat(totalPayload, buf2);
			strcat(payloadNew, buf2);
		} else {
			strcat(payloadNew, ".");
			strcat(totalPayload, ".");
		}
		data++;
	}
}
//Function to retrieve arguments from command line and set corresponding flags.Error handling of wrong options and missing arguments
int get_args(int *iflag, int *fflag, int *sflag, int* eflag, char* interface,
		char* fileName, char* string, char* expression, char*argv[], int argc) {
	*iflag = *fflag = *sflag = *eflag = 0;
	int nextarg = 4;
	int i = 1;
	for (i = 1; i < argc; i++) {
		if (strcmp("-i", argv[i]) == 0) {
			nextarg = 1;
		} else if (strcmp("-r", argv[i]) == 0) {
			nextarg = 2;
		} else if (strcmp("-s", argv[i]) == 0) {
			nextarg = 3;
		} else {
			nextarg = 4;
		}
		if (nextarg == 1) {
			i++;
			if (i >= argc) {
				fprintf(stderr, "-i expects interface name.\n");
				exit(0);
			}
			strcpy(interface, argv[i]);
			*iflag = 1;
		} else if (nextarg == 2) {
			i++;
			if (i >= argc) {
				fprintf(stderr, "-r expects filename.\n");
				exit(0);
			}
			strcpy(fileName, argv[i]);
			*fflag = 1;
		} else if (nextarg == 3) {
			i++;
			if (i >= argc) {
				fprintf(stderr, "-s expects string.\n");
				exit(0);
			}
			strcpy(string, argv[i]);
			*sflag = 1;
		} else {
			strcat(expression, argv[i]);
			strcat(expression, " ");
			*eflag = 1;
		}
	}
	return 1;

}
//convert payload to printable format with 16 bytes on each line and corresponding ASCII characters on the right
void printPayload(u_char* payload, int size, char* payloadNew,
		char* totalPayload) {
	u_char* data = payload;
	u_char* start = payload;
	char buf[size];
	char buf2[size];
	if (size <= 16) {
		printLastLine(data, size, payloadNew, totalPayload);
	} else {
		int total_lines = size / 16;
		int data_rem = size;
		int i = 0;
		for (i = 0; i < total_lines; i++) {
			data = start;
			int m = 0;
			for (m = 0; m < 16; m++) {
				sprintf(buf, "%02x ", *data);
				strcat(totalPayload, buf);
				data++;
			}
			data_rem = data_rem - 16;
			data = start;
			int l = 0;
			//fprintf(stdout, "  ");
			strcat(totalPayload, "  ");
			for (l = 0; l < 16; l++) {
				if (isprint(*data)) {
					sprintf(buf2, "%c", *data);
					strcat(totalPayload, buf2);
					strcat(payloadNew, buf2);
				} else {
					strcat(payloadNew, ".");
					strcat(totalPayload, ".");
				}
				data++;
			}
			strcat(totalPayload, "\n");
			start = start + 16;
		}
		if (data_rem != 0) {
			printLastLine(start, data_rem, payloadNew, totalPayload);
			data_rem = 0;
		}
	}

}

//convert ethernet address to printable format.
char *ether_ntoa_rz(const struct ether_addr *addr, char *buf)
{
    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
            addr->ether_addr_octet[0], addr->ether_addr_octet[1],
            addr->ether_addr_octet[2], addr->ether_addr_octet[3],
            addr->ether_addr_octet[4], addr->ether_addr_octet[5]);
    return buf;
}
void process_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet) {
	ethernet = (struct sniff_ethernet*) (packet);
	// retrieve timestamp and convert it to printable format
	struct timeval tv;
	time_t nowtime;
	struct tm *nowtm;
	char tmbuf[64], buf[64];
	tv = header->ts;
	nowtime = tv.tv_sec;
	nowtm = localtime(&nowtime);
	strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);
	snprintf(buf, sizeof buf, "%s.%06ld", tmbuf, tv.tv_usec);
	pdt.timestamp = buf;

	//Retrieving data from ethernet header,source mac address,destination mac address,ether_type and header_len
	char ether_src[100];
	char ether_dst[100];
	static char addrbuf[18];
	strcpy(ether_dst, ether_ntoa_rz((struct ether_addr *) ethernet->ether_dhost,addrbuf));
	strcpy(ether_src, ether_ntoa_rz((struct ether_addr *) ethernet->ether_shost,addrbuf));
	pdt.ether_type = ethernet->ether_type;
	pdt.len = header->len;

	//Shift pointer to IP header and retrieving source,destination ip address,protocol type.
	ip = (struct sniff_ip*) (packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip) * 4;
	char *tmp = inet_ntoa(ip->ip_dst);
	char dstaddr[100];
	strcpy(dstaddr, tmp);
	char srcaddr[100];
	tmp = inet_ntoa(ip->ip_src);
	strcpy(srcaddr, tmp);
	switch (ip->ip_p) {
	case IPPROTO_TCP:
		pdt.protocol = "TCP";
		break;
	case IPPROTO_UDP:
		pdt.protocol = "UDP";
		break;
	case IPPROTO_ICMP:
		pdt.protocol = "ICMP";
		break;
	default:
		pdt.protocol = "OTHER";
		break;
	}
	//shift pointer to the next header(TCP,UDP,ICMP,OTHER) and retrieving port numbers if any.
	if (strcmp("TCP", pdt.protocol) == 0) {
		tcp = (struct sniff_tcp*) (packet + SIZE_ETHERNET + size_ip);
		size_packet = TH_OFF(tcp) * 4;
		pdt.dst_port = tcp->th_dport;
		pdt.src_port = tcp->th_sport;
	}
	if (strcmp("UDP", pdt.protocol) == 0) {
		udp = (struct sniff_udphdr*) (packet + SIZE_ETHERNET + size_ip);
		pdt.dst_port = udp->dest;
		pdt.src_port = udp->source;
		size_packet = sizeof(struct sniff_udphdr);
	}
	if (strcmp("ICMP", pdt.protocol) == 0) {
		icmp = (struct sniff_icmphdr*) (packet + SIZE_ETHERNET + size_ip);
		size_packet = sizeof(struct sniff_icmphdr);
	}

	//shift pointer to payload and convert it to printable format
	payload = (u_char *) (packet + SIZE_ETHERNET + size_ip + size_packet);
	char* occurence = NULL;
	int payload_length = 0;
	payload_length = header->caplen - (SIZE_ETHERNET + size_ip + size_packet);
	char payloadNew[payload_length * 5];
	memset(payloadNew, 0, sizeof payloadNew);
	char totalPayload[payload_length * 5];
	memset(totalPayload, 0, sizeof totalPayload);
	if (payload_length > 0) {
		printPayload(payload, payload_length, &payloadNew, &totalPayload);
	}
	// search for string in the payload if string is specified after -s option and display only those packets whose payload contains the string specified.
	if (pdt.string != NULL) {
		occurence = strstr(payloadNew, pdt.string);
	}
	if (pdt.string != NULL && occurence == NULL) {
		return;
	}
	fprintf(stdout, "\n");
	//If protocol is Other than TCP,UDP or ICMP just print the raw payload after ethernet header as IP header is not present.
	if(strcmp("OTHER", pdt.protocol) == 0){
		fprintf(stdout, "%s %s -> %s type 0x%x len %u %s\n",
				pdt.timestamp, ether_src, ether_dst, ntohs(pdt.ether_type), pdt.len,
			    pdt.protocol);
		fprintf(stdout, "%s", totalPayload);

	}
	if(strcmp("ICMP", pdt.protocol) == 0){
		 fprintf(stdout, "%s %s -> %s type 0x%x len %u %s -> %s %s\n",
					pdt.timestamp, ether_src, ether_dst, ntohs(pdt.ether_type), pdt.len,
					srcaddr, dstaddr,
					pdt.protocol);
			    fprintf(stdout, "%s", totalPayload);

		}
	else{ // If protocol is TCP,UDP or ICMP print all the fields retrieved.
	    fprintf(stdout, "%s %s -> %s type 0x%x len %u %s:%u -> %s:%u %s\n",
			pdt.timestamp, ether_src, ether_dst, ntohs(pdt.ether_type), pdt.len,
			srcaddr, ntohs(pdt.src_port), dstaddr, ntohs(pdt.dst_port),
			pdt.protocol);
	    fprintf(stdout, "%s", totalPayload);
	}
	fflush(stdout);
}
int main(int argc, char *argv[]) {
	char *fileName;
	pcap_t *handle; /* Session handle */
	char *dev; /* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
	struct bpf_program fp; /* The compiled filter */
	bpf_u_int32 mask; /* Our netmask */
	bpf_u_int32 net; /* Our IP */
	struct pcap_pkthdr header; /* The header that pcap gives us */
	const u_char *packet; /* The actual packet */
	int iflag, fflag, sflag, eflag;
	char *string;
	char inter[1024];
	char file[1024];
	char str[1024];
	char filter_exp[1024] = "";
	string = &str;
	fileName = &file;
	dev = &inter;
	get_args(&iflag, &fflag, &sflag, &eflag, dev, fileName, string, filter_exp,
			argv, argc);
    if(iflag==1 && fflag==1){
	   fprintf(stderr,"Cannot use both -i and -r\n");
	   exit(0);
    }
	/* Define the device */

	/* Open the session in promiscuous mode */
	if (iflag == 1) {
		if (dev == NULL) {
			dev = pcap_lookupdev(errbuf);
		}
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return (2);
		}
		/* Find the properties for the device */
		if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev,
					errbuf);
			net = 0;
			mask = 0;
		}
		handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			return (2);
		}
	} else if (fflag == 1) {
		handle = pcap_open_offline(fileName, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open file %s: %s\n", fileName, errbuf);
			return (2);
		}
	} else {
		dev = pcap_lookupdev(errbuf);
		handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			return (2);
		}
	}
	if (sflag == 1) {
		pdt.string = string;
	}

	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp,
				pcap_geterr(handle));
		return (2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp,
				pcap_geterr(handle));
		return (2);
	}

	pcap_loop(handle, -1, process_packet, NULL);

	pcap_freecode(&fp);
	/* And close the session */
	pcap_close(handle);
	return (0);
}

