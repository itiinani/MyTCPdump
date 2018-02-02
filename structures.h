/*
 * structures.h
 *
 *  Created on: Sep 30, 2017
 *      Author: root
 */

#ifndef STRUCTURES_H_
#define STRUCTURES_H_

typedef struct __attribute__((__packed__)) pkt_data {
  char*  timestamp;
  u_char  ether_dhost[6];	/* destination eth addr	*/
  u_char ether_shost[6];	/* source ether addr	*/
  u_int16_t ether_type;
  bpf_u_int32 len;
  u_char* protocol;
  struct in_addr src_addr;
  struct in_addr dst_addr;
  u_int16_t src_port;
  u_int16_t dst_port;
  uint16_t payload_size;
  uint8_t* payload;
  char*  string;
} pkt_data_t;

#define ETHER_ADDR_LEN	6

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
	#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
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

	struct sniff_icmphdr
	{
	  u_int8_t type;		/* message type */
	  u_int8_t code;		/* type sub-code */
	  u_int16_t checksum;
	  union
	  {
	    struct
	    {
	      u_int16_t	id;
	      u_int16_t	sequence;
	    } echo;			/* echo datagram */
	    u_int32_t	gateway;	/* gateway address */
	    struct
	    {
	      u_int16_t	__unused;
	      u_int16_t	mtu;
	    } frag;			/* path mtu discovery */
	  } un;
	};

	struct sniff_udphdr
	{
	  u_int16_t source;
	  u_int16_t dest;
	  u_int16_t len;
	  u_int16_t check;
	};
#endif /* STRUCTURES_H_ */
