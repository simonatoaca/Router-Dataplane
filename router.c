#include <arpa/inet.h> /* ntoh, hton and inet_ functions */
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "queue.h"
#include "lib.h"
#include "protocols.h"

int main(int argc, char *argv[])
{
	char packet[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

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
			!IS_BROADCAST(mac_addr)) {
			printf("The packet has another destination\n");
			continue;
		}

		/* Check if it is an IPv4 packet */
		if (eth_hdr->ether_type == ntohs(ETHERTYPE_IP)) {
			printf("Received an IPv4 packet on interface %d\n", interface);

			struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));
			continue;
		} 
		
		/* Check if it is an ARP packet */
		if (eth_hdr->ether_type == ntohs(ETHERTYPE_ARP)) {
			printf("Received an ARP packet on interface %d\n", interface);

			struct arp_header *arp_hdr = (struct arp_header *)(packet + sizeof(struct ether_header));
			continue;
		}
	}
}

