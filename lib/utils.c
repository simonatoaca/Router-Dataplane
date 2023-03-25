#include <arpa/inet.h> /* ntoh, hton and inet_ functions */
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "queue.h"
#include "lib.h"
#include "utils.h"
#include "protocols.h"

extern struct router router;

int router_init(char *rtable)
{
	router.rtable = malloc(sizeof(struct route_table_entry) * 80000);
	if (!router.rtable)
		return -1;
	
	router.arp_table = malloc(sizeof(struct arp_entry) * 100);
	if (!router.rtable) {
		free(router.rtable);
		return -1;
	}

	router.waiting_list = queue_create();
	if (!router.waiting_list) {
		free(router.rtable);
		free(router.arp_table);
		return -1;
	}
	
	/* Read the static routing table and the ARP table */
	router.rtable_len = read_rtable(rtable, router.rtable);
	//router.arp_table_len = parse_arp_table("arp_table.txt", router.arp_table);

	return 0;
}

struct route_table_entry *get_best_route(uint32_t ip_dest) {
	struct route_table_entry *candidate = NULL;

	for (int i = 0; i < router.rtable_len; i++) {
		if ((router.rtable[i].prefix & router.rtable[i].mask) == (ip_dest & router.rtable[i].mask)) {
			if (candidate == NULL || ntohl(router.rtable[i].mask) > ntohl(candidate->mask)) {
				candidate = &router.rtable[i];
			}
		}
	}

	return candidate;
}

struct arp_entry *search_arp_entry(uint32_t given_ip) {
	for (int i = 0; i < router.arp_table_len; i++) {
		if (router.arp_table[i].ip == given_ip) {
			struct arp_entry *entry = &router.arp_table[i];
			return entry;
		}
	}

	return NULL;
}

void handle_ipv4_packet(char *packet, size_t len)
{	
	struct ether_header *eth_hdr = GET_ETHR_HDR(packet);
	struct iphdr *ip_hdr = GET_IP_HDR(packet);

	/* Check ip_hdr integrity */
	if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr))) {
		printf("Corrupt packet\n");
		return;
	}

	/* Find the best route for the packet */
	struct route_table_entry *route = get_best_route(ip_hdr->daddr);

	if (!route) {
		printf("No route found for the packet\n");
		return;
	}

	if (!ip_hdr->ttl) {
		/* AICI TRB RASPUNS ICMP */
		printf("TTL is 0\n");
		return;
	}

	/* Update ttl */
	ip_hdr->ttl--;
	ip_hdr->check = 0;

	/* Recompute the checksum */
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

	/* Update ethernet addresses */
	get_interface_mac(route->interface, eth_hdr->ether_shost);

	struct arp_entry *arp_entry = search_arp_entry(route->next_hop);

	/* If the MAC address was not in the ARP table, send an ARP request and wait */
	if (!arp_entry) {
		/* ARP REQUEST PE next hop -> coada -> astept ARP reply -> trimit pachetul */
		printf("The ip addr was not in the ARP table\n");

		/* Get interface ip */
		struct in_addr ip_addr;
		inet_aton(get_interface_ip(route->interface), &ip_addr);
		uint32_t ip = ip_addr.s_addr;

		/* Populate ARP request packet */
		struct ether_header eth_arp_hdr = ETH_HDR_ARP_REQ();
		memcpy(eth_arp_hdr.ether_shost, eth_hdr->ether_shost, 6 * sizeof(uint8_t));

		struct arp_header arp_hdr = ARP_REQ_HDR(ip, route->next_hop);
		memcpy(arp_hdr.sha, eth_hdr->ether_shost, 6 * sizeof(uint8_t));

		char arp_request[MAX_PACKET_LEN];
		memcpy(arp_request, &eth_arp_hdr, sizeof(struct ether_header));
		memcpy(arp_request + sizeof(struct ether_header), &arp_hdr, sizeof(struct arp_header));

		queue_enq(router.waiting_list, packet);

		printf("Send ARP REQUEST on interface %d\n", route->interface);
		int arp_req_len = sizeof(struct ether_header) + sizeof(struct arp_header);
		send_to_link(route->interface, arp_request, arp_req_len);
		return;
	}

	memcpy(eth_hdr->ether_dhost, arp_entry->mac, sizeof(eth_hdr->ether_dhost));
		  
	// Send packet
	send_to_link(route->interface, packet, len);
	printf("\n");
}

void handle_arp_packet(char *packet, size_t len, int interface)
{
	struct ether_header *eth_hdr = GET_ETHR_HDR(packet);
	struct arp_header *arp_hdr = GET_ARP_HDR(packet);

	if (arp_hdr->op == ntohs(ARP_REQUEST_CODE)) {
		printf("Got an ARP request on interface %d\n", interface);

		/* Check if the request asks for the MAC of the router */
		struct in_addr ip_addr;
		inet_aton(get_interface_ip(interface), &ip_addr);
		uint32_t ip = ip_addr.s_addr;
		uint8_t *ip_bytes = (uint8_t *)&ip;

		printf("current ip: %d.%d.%d.%d\n", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);

		uint8_t *searched_ip = (uint8_t *)&arp_hdr->tpa;
		printf("searched ip: %d.%d.%d.%d\n", searched_ip[0], searched_ip[1], searched_ip[2], searched_ip[3]);

		if (ip == arp_hdr->tpa) {
			/* Send ARP reply */
			arp_hdr->op = htons(ARP_REPLY_CODE);
			
			memcpy(arp_hdr->tha, arp_hdr->sha, sizeof(arp_hdr->tha));
			memcpy(&arp_hdr->tpa, &arp_hdr->spa, sizeof(arp_hdr->tpa));
			memcpy(&arp_hdr->spa, &ip, sizeof(arp_hdr->spa));
			
			/* Update ethernet addresses */
			uint8_t *mac_addr = eth_hdr->ether_shost;
			get_interface_mac(interface, eth_hdr->ether_shost);
			memcpy(arp_hdr->sha, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
			memcpy(eth_hdr->ether_dhost, mac_addr, sizeof(eth_hdr->ether_dhost));

			send_to_link(interface, packet, len);
			printf("Sent ARP reply on interface: %d, with the MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n\n", \
				interface, mac_addr[0], mac_addr[1], \
				mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
		}
	}

	if (arp_hdr->op == ntohs(ARP_REPLY_CODE)) {
		printf("Got an ARP reply on interface %d\n\n", interface);

		struct arp_entry arp_entry;
		memcpy(arp_entry.mac, arp_hdr->sha, sizeof(arp_hdr->sha));
		arp_entry.ip = arp_hdr->spa;

		memcpy(&router.arp_table[router.arp_table_len], &arp_entry, sizeof(struct arp_entry));
		router.arp_table_len++;

		/* Go through waiting packets */
		if (queue_empty(router.waiting_list)) {
			printf("No one was waiting for this ARP reply\n");
			return;
		}

		char *waiting_packet = queue_deq(router.waiting_list);
		
		struct ether_header *eth_hdr_waiting = GET_ETHR_HDR(waiting_packet);
		struct arp_header *arp_hdr_waiting = GET_ARP_HDR(waiting_packet);

		if (arp_hdr_waiting->tpa == arp_hdr->spa) {
			memcpy(eth_hdr_waiting->ether_dhost, arp_entry.mac, sizeof(eth_hdr_waiting->ether_dhost));
			
			// Send packet
			send_to_link(interface, waiting_packet, strlen(waiting_packet));
			printf("Sent waiting packet\n");
		}
	}
}