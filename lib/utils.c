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
	
	/* Read the static routing table */
	router.rtable_len = read_rtable(rtable, router.rtable);

	return 0;
}

static struct route_table_entry *get_best_route(uint32_t ip_dest) {
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

static struct arp_entry *search_arp_entry(uint32_t given_ip) {
	for (int i = 0; i < router.arp_table_len; i++) {
		if (router.arp_table[i].ip == given_ip) {
			struct arp_entry *entry = &router.arp_table[i];
			return entry;
		}
	}

	return NULL;
}

static void enqueue_packet(char *packet, size_t len, uint32_t next_hop, queue q)
{
	struct w_packet *aux_packet = malloc(sizeof(struct w_packet));

	memcpy(aux_packet->packet, packet, MAX_PACKET_LEN);
	aux_packet->len = len;
	aux_packet->next_hop = next_hop;
	queue_enq(q, aux_packet);
}

static void send_arp_request(struct route_table_entry *route, struct ether_header *eth_hdr)
{
	/* Get interface ip */
	struct in_addr ip_addr;
	inet_aton(get_interface_ip(route->interface), &ip_addr);
	uint32_t ip = ip_addr.s_addr;

	/* Populate ARP request packet */
	struct ether_header eth_arp_hdr = ETH_HDR_ARP_REQ();
	memcpy(eth_arp_hdr.ether_shost, eth_hdr->ether_shost, MAC_ADDR_SIZE);

	struct arp_header arp_hdr = ARP_REQ_HDR(ip, route->next_hop);
	memcpy(arp_hdr.sha, eth_hdr->ether_shost, MAC_ADDR_SIZE);

	char arp_request[MAX_PACKET_LEN];
	memcpy(arp_request, &eth_arp_hdr, sizeof(struct ether_header));
	memcpy(arp_request + sizeof(struct ether_header), &arp_hdr, sizeof(struct arp_header));

	int arp_req_len = sizeof(struct ether_header) + sizeof(struct arp_header);
	send_to_link(route->interface, arp_request, arp_req_len);
}

static void send_arp_reply(char *packet, size_t len, uint32_t ip, int interface)
{
	struct ether_header *eth_hdr = GET_ETHR_HDR(packet);
	struct arp_header *arp_hdr = GET_ARP_HDR(packet);

	/* Send ARP reply */
	arp_hdr->op = htons(ARP_REPLY_CODE);
			
	memcpy(arp_hdr->tha, arp_hdr->sha, MAC_ADDR_SIZE);

	arp_hdr->tpa = arp_hdr->spa;
	arp_hdr->spa = ip;

	/* Update ethernet addresses */
	uint8_t mac_addr[6];
	memcpy(mac_addr, eth_hdr->ether_shost, MAC_ADDR_SIZE);

	get_interface_mac(interface, eth_hdr->ether_shost);
	memcpy(arp_hdr->sha, eth_hdr->ether_shost, MAC_ADDR_SIZE);
	memcpy(eth_hdr->ether_dhost, mac_addr, MAC_ADDR_SIZE);

	send_to_link(interface, packet, len);
}

static void send_waiting_packets(int interface, uint32_t recv_ip, uint8_t *recv_mac)
{
	if (queue_empty(router.waiting_list)) {
		return;
	}

	queue temp_q = queue_create();

	/* Send all packets that were waiting for this reply */
	while (!queue_empty(router.waiting_list)) {
		struct w_packet *w_packet = queue_deq(router.waiting_list);

		struct ether_header *eth_hdr_waiting = GET_ETHR_HDR(w_packet->packet);

		/* If the packet waited for this ip address mac, send it */
		if (w_packet->next_hop == recv_ip) {
			memcpy(eth_hdr_waiting->ether_dhost, recv_mac, MAC_ADDR_SIZE);
				
			send_to_link(interface, w_packet->packet, w_packet->len);
			free(w_packet);
			continue;
		}

		enqueue_packet(w_packet->packet, w_packet->len, w_packet->next_hop, temp_q);
		free(w_packet);
	}

	/* Update waiting list */
	router.waiting_list = temp_q;
}

static void build_ping_reply(char *packet, int len)
{
	struct ether_header *eth_hdr = GET_ETHR_HDR(packet);
	struct iphdr *ip_hdr = GET_IP_HDR(packet);
	struct icmphdr *icmp_hdr = GET_ICMP_HDR(packet);

	/* Swap shost and dhost in ethernet */
	uint8_t aux_mac[6];
	memcpy(aux_mac, eth_hdr->ether_shost, MAC_ADDR_SIZE);
	memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, MAC_ADDR_SIZE);
	memcpy(eth_hdr->ether_dhost, aux_mac, MAC_ADDR_SIZE);

	/* Swap saddr and daddr */
	uint32_t aux_ip = ip_hdr->saddr;
	ip_hdr->saddr = ip_hdr->daddr;
	ip_hdr->daddr = aux_ip;

	/* Change ICMP type to indicate a reply */
	icmp_hdr->type = ICMP_REPLY;

	/* ICMP checksum */
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr,
								len - sizeof(struct ether_header) - sizeof(struct iphdr)));
}

static void build_icmp_msg(char *packet, int interface, size_t *len, uint32_t ip, uint8_t error_type)
{
	struct ether_header *eth_hdr = GET_ETHR_HDR(packet);
	struct iphdr *ip_hdr = GET_IP_HDR(packet);

	/* Copy iphdr and 64 bytes at the end */
	char payload[ICMP_PAYLOAD_SZ];
	memcpy(payload, packet + sizeof(struct ether_header), ICMP_PAYLOAD_SZ);
	memset(packet + sizeof(struct ether_header) + sizeof(struct iphdr), 0, sizeof(struct icmphdr));
	memcpy(packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr),
			payload, ICMP_PAYLOAD_SZ);

	/* Set source and destination addresses */
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, MAC_ADDR_SIZE);
	get_interface_mac(interface, eth_hdr->ether_shost);

	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = ip;

	ip_hdr->protocol = ICMP_PROT;

	struct icmphdr *icmp_hdr = GET_ICMP_HDR(packet);

	/* Update len */
	(*len) += sizeof(struct icmphdr);
	ip_hdr->tot_len += sizeof(struct icmphdr);

	/* Change ICMP type to indicate the error */
	icmp_hdr->type = error_type;
	icmp_hdr->code = 0;

	/* ICMP checksum */
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr,
							(*len) - sizeof(struct ether_header) - sizeof(struct iphdr)));
}

static uint32_t get_ip_from_interface(int interface)
{
	struct in_addr ip_addr;
	inet_aton(get_interface_ip(interface), &ip_addr);
	return ip_addr.s_addr;
}

void handle_ipv4_packet(char *packet, size_t len, int interface)
{	
	struct ether_header *eth_hdr = GET_ETHR_HDR(packet);
	struct iphdr *ip_hdr = GET_IP_HDR(packet);

	/* Check ip_hdr integrity */
	if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr))) {
		return;
	}

	uint32_t ip = get_ip_from_interface(interface);

	/* Check if this was a ping to the router */
	if (ip_hdr->daddr == ip && ip_hdr->protocol == ICMP_PROT) {
		struct icmphdr *icmp_hdr = GET_ICMP_HDR(packet);

		if (icmp_hdr->type == ICMP_REQUEST) {
			build_ping_reply(packet, len);
		}
	}

	/* Find the best route for the packet */
	struct route_table_entry *route = get_best_route(ip_hdr->daddr);

	if (!route) {
		build_icmp_msg(packet, interface, &len, ip, ICMP_DEST_UNREACHABLE);

		/* Find new route */
		route = get_best_route(ip_hdr->daddr);
	}

	/* Update ttl */
	ip_hdr->ttl--;

	if (!ip_hdr->ttl) {
		build_icmp_msg(packet, interface, &len, ip, ICMP_TIME_EXCEEDED);

		/* Find new route */
		route = get_best_route(ip_hdr->daddr);
	}


	ip_hdr->check = 0;

	/* Recompute the checksum */
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

	/* Update source ethernet address */
	get_interface_mac(route->interface, eth_hdr->ether_shost);

	struct arp_entry *arp_entry = search_arp_entry(route->next_hop);

	/* If the MAC address was not in the ARP table, send an ARP request and wait */
	if (!arp_entry) {
		enqueue_packet(packet, len, route->next_hop, router.waiting_list);

		send_arp_request(route, eth_hdr);
		return;
	}

	memcpy(eth_hdr->ether_dhost, arp_entry->mac, MAC_ADDR_SIZE);
		  
	/* Send packet */
	send_to_link(route->interface, packet, len);
}

void handle_arp_packet(char *packet, size_t len, int interface)
{
	struct arp_header *arp_hdr = GET_ARP_HDR(packet);

	if (arp_hdr->op == ntohs(ARP_REQUEST_CODE)) {
		/* Check if the request asks for the MAC of the router */
		uint32_t ip = get_ip_from_interface(interface);

		if (ip == arp_hdr->tpa) {
			send_arp_reply(packet, len, ip, interface);
		}
	}

	if (arp_hdr->op == ntohs(ARP_REPLY_CODE)) {
		struct arp_entry arp_entry;
		memcpy(arp_entry.mac, arp_hdr->sha, MAC_ADDR_SIZE);
		arp_entry.ip = arp_hdr->spa;

		memcpy(&router.arp_table[router.arp_table_len], &arp_entry, sizeof(struct arp_entry));
		router.arp_table_len++;

		send_waiting_packets(interface, arp_hdr->spa, arp_entry.mac);
	}
}