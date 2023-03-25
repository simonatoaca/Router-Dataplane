#include <arpa/inet.h> /* ntoh, hton and inet_ functions */
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
	
	/* Read the static routing table and the ARP table */
	router.rtable_len = read_rtable(rtable, router.rtable);
	router.arp_table_len = parse_arp_table("arp_table.txt", router.arp_table);

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

struct arp_entry *get_arp_entry(uint32_t given_ip) {
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

	/*
		TREBUIE VERIFICAT DACA ROUTERUL E DESTINATIA -> ICMP DACA NU E
	*/

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

	/* ARP REQUEST PE next hop -> coada -> astept ARP reply -> trimit pachetul */
	struct arp_entry *arp_entry = get_arp_entry(route->next_hop);
	memcpy(eth_hdr->ether_dhost, arp_entry->mac, sizeof(eth_hdr->ether_dhost));
		  
	// Send packet
	send_to_link(route->interface, packet, len);
	printf("\n");
}