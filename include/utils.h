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

#define GET_ETHR_HDR(packet) \
	(struct ether_header *) packet

#define GET_IP_HDR(packet) \
	(struct iphdr *)(packet + sizeof(struct ether_header))

#define GET_ARP_HDR(packet) \
	(struct arp_header *)(packet + sizeof(struct ether_header))


/*
	@brief Initializes internal router structs and loads the routing table
	@param rtable the file where the routing table is found 
	@return 0 on success, -1 if it fails
*/
int router_init(char *rtable);

/*
 	@brief returns the best route for the packet, or NULL if there
 	is no matching route.
*/
struct route_table_entry *get_best_route(uint32_t ip_dest);
struct arp_entry *get_arp_entry(uint32_t given_ip);

void handle_ipv4_packet(char *packet, size_t len);

#endif