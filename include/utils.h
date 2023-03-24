#ifndef _UTILS_H_
#define _UTILS_H_

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806

#define MAC_ADDR_EQ(mac_addr, compared_to) \
	(mac_addr[0] == compared_to[0] &&	\
		mac_addr[1] == compared_to[1] &&	\
		mac_addr[2] == compared_to[2] &&	\
		mac_addr[3] == compared_to[3] &&	\
		mac_addr[4] == compared_to[4] &&	\
		mac_addr[5] == compared_to[5])

#define IS_BROADCAST(mac_addr) \
	(mac_addr[0] == 255 &&	\
		mac_addr[1] == 255 &&	\
	 	mac_addr[2] == 255 &&	\
	 	mac_addr[3] == 255 &&	\
	 	mac_addr[4] == 255 &&	\
	 	mac_addr[5] == 255)

#define GET_IP_HDR(packet) \
	(struct iphdr *)(packet + sizeof(struct ether_header))

#define GET_ARP_HDR(packet) \
	(struct arp_header *)(packet + sizeof(struct ether_header))

#endif