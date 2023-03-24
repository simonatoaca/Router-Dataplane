#include <arpa/inet.h> /* ntoh, hton and inet_ functions */
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "queue.h"
#include "lib.h"
#include "utils.h"
#include "protocols.h"

/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* Arp table */
struct arp_entry *arp_table;
int arp_table_len;

/*
 Returns a pointer (eg. &rtable[i]) to the best matching route, or NULL if there
 is no matching route.
*/
struct route_table_entry *get_best_route(uint32_t ip_dest) {
	struct route_table_entry *candidate = NULL;

	for (int i = 0; i < rtable_len; i++) {
		if ((rtable[i].prefix & rtable[i].mask) == (ip_dest & rtable[i].mask)) {
			if (candidate == NULL || ntohl(rtable[i].mask) > ntohl(candidate->mask)) {
				candidate = &rtable[i];
			}
		}
	}

	return candidate;
}

struct arp_entry *get_arp_entry(uint32_t given_ip) {
	for (int i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == given_ip) {
			struct arp_entry *entry = &arp_table[i];
			return entry;
		}
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	char packet[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	rtable = malloc(sizeof(struct route_table_entry) * 80000);
	DIE(rtable == NULL, "memory");

	arp_table = malloc(sizeof(struct arp_entry) * 100);
	DIE(arp_table == NULL, "memory");
	
	/* Read the static routing table and the ARP table */
	rtable_len = read_rtable(argv[1], rtable);
	arp_table_len = parse_arp_table("arp_table.txt", arp_table);

	while (1) {
		int interface;
		size_t len;

		interface = recv_from_any_link(packet, &len);
		DIE(interface < 0, "recv_from_any_links");

		uint8_t mac_addr[6];
		get_interface_mac(interface, mac_addr);
		printf("Interface: %d, MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", \
			interface, mac_addr[0], mac_addr[1], \
			mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);

		struct ether_header *eth_hdr = (struct ether_header *) packet;

		printf("Ethernet dest: %02x:%02x:%02x:%02x:%02x:%02x\n", \
			eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], \
			eth_hdr->ether_dhost[2], eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);

		/* Check if the packet is for this device */
		if (!MAC_ADDR_EQ(eth_hdr->ether_dhost, mac_addr) &&
			!IS_BROADCAST(eth_hdr->ether_dhost)) {
			printf("The packet has another destination\n");
			continue;
		}

		/* Check if it is an IPv4 packet */
		if (eth_hdr->ether_type == ntohs(ETHERTYPE_IP)) {
			printf("Received an IPv4 packet on interface %d\n", interface);
			
			struct iphdr *ip_hdr = GET_IP_HDR(packet);

			/* Check ip_hdr integrity */
			if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr))) {
				printf("Corrupt packet\n");
				continue;
			}

			/*
				TREBUIE VERIFICAT DACA ROUTERUL E DESTINATIA -> ICMP
			*/

			/* Find the best route for the packet */
			struct route_table_entry *route = get_best_route(ip_hdr->daddr);

			if (!route) {
				printf("No route found for the packet\n");
				continue;
			}

			if (!ip_hdr->ttl) {
				printf("TTL is 0\n");
				continue;
			}

			/* Update ttl */
			ip_hdr->ttl--;
			ip_hdr->check = 0;

			/* Recompute the checksum */
			ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

			/* Update ethernet addresses */
			get_interface_mac(route->interface, eth_hdr->ether_shost);
			struct arp_entry *arp_entry = get_arp_entry(route->next_hop);
			memcpy(eth_hdr->ether_dhost, arp_entry->mac, sizeof(eth_hdr->ether_dhost));
		  
			// Send packet
			send_to_link(route->interface, packet, len);
			printf("\n");
			continue;
		} 
		
		/* Check if it is an ARP packet */
		if (eth_hdr->ether_type == ntohs(ETHERTYPE_ARP)) {
			printf("Received an ARP packet on interface %d\n", interface);

			struct arp_header *arp_hdr = GET_ARP_HDR(packet);
			continue;
		}
	}

	free(rtable);
	free(arp_table);
}

