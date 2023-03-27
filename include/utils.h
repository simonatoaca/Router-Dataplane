#ifndef _UTILS_H_
#define _UTILS_H_

#include "protocols.h"

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806

#define BROADCAST_MAC {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
#define MAC_ADDR_SIZE 6 * sizeof(uint8_t)
#define ICMP_PAYLOAD_SZ sizeof(struct iphdr) + 64

#define ARP_REQUEST_CODE 1
#define ARP_REPLY_CODE 2

#define ICMP_PROT 1

#define ETHERNET_HTYPE 1

/* ICMP TYPES */
#define ICMP_REPLY 0
#define ICMP_REQUEST 8
#define ICMP_TIME_EXCEEDED 11
#define ICMP_DEST_UNREACHABLE 3

#define MAC_ADDR_EQ(mac_addr, compared_to) \
	(mac_addr[0] == compared_to[0] &&	\
		mac_addr[1] == compared_to[1] &&	\
		mac_addr[2] == compared_to[2] &&	\
		mac_addr[3] == compared_to[3] &&	\
		mac_addr[4] == compared_to[4] &&	\
		mac_addr[5] == compared_to[5])

#define IS_BROADCAST(mac_addr) \
	(mac_addr[0] == 0xFF &&	\
		mac_addr[1] == 0xFF &&	\
	 	mac_addr[2] == 0xFF &&	\
	 	mac_addr[3] == 0xFF &&	\
	 	mac_addr[4] == 0xFF &&	\
	 	mac_addr[5] == 0xFF)

#define GET_ETHR_HDR(packet) \
	(struct ether_header *) packet

#define GET_IP_HDR(packet) \
	(struct iphdr *)(packet + sizeof(struct ether_header))

#define GET_ARP_HDR(packet) \
	(struct arp_header *)(packet + sizeof(struct ether_header))

#define GET_ICMP_HDR(packet) \
	(struct icmphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr))

#define ETH_HDR_ARP_REQ() (struct ether_header) {				\
	.ether_dhost = BROADCAST_MAC,								\
	.ether_shost = {0},											\
	.ether_type = htons(ETHERTYPE_ARP)							\
}

#define ARP_REQ_HDR(source_ip, dest_ip) (struct arp_header) {	\
		.htype = htons(ETHERNET_HTYPE),										\
		.ptype = htons(ETHERTYPE_IP), 							\
		.hlen = 6, 												\
		.plen = 4,												\
		.op = htons(ARP_REQUEST_CODE), 							\
		.sha = {0}, 											\
		.spa = source_ip, 										\
		.tha = {0}, 											\
		.tpa = dest_ip											\
}

/* Struct used for storing the packets waiting for ARP reply */
struct w_packet {
	char packet[MAX_PACKET_LEN];
	uint32_t next_hop;
	size_t len;
};

/*
	@brief Initializes internal router structs and loads the routing table
	@param rtable the file where the routing table is found 
	@return 0 on success, -1 if it fails
*/
int router_init(char *rtable);

/*
	@brief finds the next hop for the ip destination
	@param ip_dest the final destination of the packet
	@return route_table_entry struct with the next hop ip and interface
*/
struct route_table_entry *get_best_route(uint32_t ip_dest);

/*
	@brief finds the mac address of the given ip in the arp table
	@param given_ip the ip of the next hop
	@return an arp_entry struct, or NULL when the given ip is not in the ARP table
*/
struct arp_entry *search_arp_entry(uint32_t given_ip);

/*
	@brief enqueues a packet in the waiting line of the router as a w_packet struct
	@param packet the enqueued packet
	@param len the length of the packet
	@param next_hop the next_hop of the packet
	@param q the queue - usually the router waiting line
*/
void enqueue_packet(char *packet, size_t len, uint32_t next_hop, queue q);

/*
	@brief sends an ARP request on route->interface,
			asking for route->next_hop ip's MAC address
	@param route a struct that contains info about the next hop
	@param eth_hdr the ether header of the packet that waits for the MAC address
*/
void send_arp_request(struct route_table_entry *route, struct ether_header *eth_hdr);

/*
	@brief sends an ARP reply with the MAC address of the interface
	@param packet the received ARP request packet
	@param len the length of the ARP request
	@param ip the ip of the interface
	@param interface the interface on which the ARP request came
*/
void send_arp_reply(char *packet, size_t len, uint32_t ip, int interface);

/*
	@brief goes through the router's waiting line and sends the packets that waited
		for an ARP reply with recv_ip's MAC address
	@param interface the interface on which the ARP reply came
	@param recv_ip the ip of the next hop for the waiting packets
	@param recv_mac the MAC address of the recv_ip
*/
void send_waiting_packets(int interface, uint32_t recv_ip, uint8_t *recv_mac);

/*
	@brief build a ping reply from a ping request
	@param packet the ping request packet -> will be modified into a reply
	@param len the length of the packet
*/
void build_ping_reply(char *packet, int len);

/*
	@brief builds an icmp message from a received packet that encountered an error
	@param packet the received packet -> headers are modified + an ICMP header is inserted
	@param interface the interface on which the original packet came
	@param len the length of the packet
	@param ip the ip of the interface
	@param error_type the error type to be inserted into the ICMP header
*/
void build_icmp_msg(char *packet, int interface, size_t *len, uint32_t ip, uint8_t error_type);

/*
	@brief gets the ip of the interface in uint32_t format
*/
uint32_t get_ip_from_interface(int interface);

/*
	@brief handles an IPv4 packet by sending it to the next hop;
			also handles ping requests
	@param packet the received packet
	@param len the length of the packet
	@param interface the interface on which the packet was received
*/
void handle_ipv4_packet(char *packet, size_t len, int interface);

/*
	@brief responds to ARP requests and sends packets on ARP replies
	@param packet the received ARP packet
	@param len the length of the packet
	@interface the interface on which the packet was received
*/
void handle_arp_packet(char *packet, size_t len, int interface);


#endif