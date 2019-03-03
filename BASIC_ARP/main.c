// Matthew Todd Geiger
// Basic ARP

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <asm/types.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <arpa/inet.h>

#define HW_TYPE 1           // ARP Code for ethernet type hardware
#define MAC_LENGTH 6        // MAC address length in bytes
#define IPV4_LENGTH 4       // IP address length in bytes
#define ARP_REQUEST 0x01    // ARP request opcode

#define debug(x...) \
    printf(x);      \
    printf("\n");
#define info(x...) \
    printf(x);     \
    printf("\n");
#define warn(x...) \
    printf(x);     \
    printf("\n");
#define err(x...) \
    perror(x);    \
    fprintf(stderr, "\n");

// ARP protocol structure
struct arp_header
{
    unsigned short hardware_type;               // ethernet, radio, etc..
    unsigned short protocol_type;               // ip..
    unsigned char hardware_len;                 // MAC length
    unsigned char protocol_len;                 // ip length
    unsigned short opcode;                      // ARP opcode can be a reply or request ARP packet
    unsigned char sender_mac[MAC_LENGTH];
    unsigned char sender_ip[IPV4_LENGTH];
    unsigned char target_mac[MAC_LENGTH];
    unsigned char target_ip[IPV4_LENGTH];
};

int main(const int argc, const char *argv[]) {
    // Check for correct usage
    if(argc != 3) {
        info("Usage: %s <INTERFACE> <TARGET_IP>", argv[0]);
        exit(EXIT_SUCCESS);
    }

    // Assign command line arguments
    const char *target_ip = argv[2];
    const char *interface = argv[1];

    // Create raw socket
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if(sockfd < 0) {
        err("Failed to open socket");
        goto out;
    }

    // Create packet recieved and delivered buffers
    char packet_out[64];
    char packet_in[64]; 

    // Create variable for interface mac and index number
    char if_mac[8];
    int if_index;
    struct ifreq ifr;

    // Copy argument in ifr for ioctl request
    strcpy(ifr.ifr_name, interface);

    // Request socket for index number of interface name argument
    if(ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {
        err("Failed to get interface index value");
        goto out;
    }

    // Save index number
    if_index = ifr.ifr_ifindex;

    // Request socket for mac address
    if(ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
        err("Failed to get interface MAC address");
        goto out;
    }

    // Save mac address
    memcpy(if_mac, ifr.ifr_hwaddr.sa_data, MAC_LENGTH);

    // Request socket for ipv4 address
    if(ioctl(sockfd, SIOCGIFADDR, &ifr) == -1) {
        err("Failed to get ip address");
        goto out;
    }

    // Create variables and structs to help with saving and translating
    // ipv4 address for terminal output
    uint32_t ip;
    struct sockaddr_in *sin_ptr;
    sin_ptr = (struct sockaddr_in *)&ifr.ifr_addr;      // Point to ipv4 address value
    ip = sin_ptr->sin_addr.s_addr;

    struct in_addr *in = (struct in_addr *)&ip;         // Use in_addr struct for use in inet_ntoa function

    debug("Interface MAC: %02X:%02X:%02X:%02X:%02X:%02X",
          if_mac[0] & 0xff,
          if_mac[1] & 0xff,
          if_mac[2] & 0xff,
          if_mac[3] & 0xff,
          if_mac[4] & 0xff,
          if_mac[5] & 0xff);

    debug("Interface IP: %s", inet_ntoa(*in));

    debug("Target IP: %s", target_ip);

    // Create header pointers for output packet
    struct ethhdr *eth = (struct ethhdr *)packet_out;
    struct arp_header *arp = (struct arp_header *)(packet_out + sizeof(struct ethhdr));

    // Set ethernet header parameters
    memset(eth->h_dest, 0xff, MAC_LENGTH);          // Destination mac set to all 0xff, all 0xff mac will broadcast to all machines
    memcpy(eth->h_source, if_mac, MAC_LENGTH);      // Source mac from interface
    eth->h_proto = htons(ETH_P_ARP);                // Follow arp protocol

    // Set ARP header parameters
    arp->hardware_len = MAC_LENGTH;                 // Assign MAC length
    arp->hardware_type = htons(HW_TYPE);            // Hardware type of 1. value 1 is ethernet hardware type
    arp->opcode = htons(ARP_REQUEST);               // Assign opcode arp request
    arp->protocol_len = IPV4_LENGTH;                // Assign IPv4 length
    arp->protocol_type = htons(ETH_P_IP);           // Set protocol type to IP
    memcpy(arp->sender_ip, &ip, IPV4_LENGTH);       // Apply your IP address
    memcpy(arp->sender_mac, if_mac, MAC_LENGTH);    // Apply your MAC address
    memset(arp->target_mac, 0xff, MAC_LENGTH);      // Destination mac set to all 0xff for broadcast
    uint32_t ip_temp = inet_addr(target_ip);        // Translate ip address from string to unsigned int
    memcpy(arp->target_ip, &ip_temp, IPV4_LENGTH);  // Copy ip address

    // Create sockaddr_ll for binding properties
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(struct sockaddr_ll));    // Set to 0
    sll.sll_family = AF_PACKET;                     // AF_PACKET socket type
    sll.sll_ifindex = if_index;                     // Index number

    // Bind socket info with sll info
    if(bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        err("Failed to bind socket information");
        goto out;
    }

    // Reuse sll for sockaddr info for sendto() function
    memcpy(&sll.sll_addr, if_mac, MAC_LENGTH);
    sll.sll_halen = MAC_LENGTH;                     // Set mac length
    sll.sll_hatype = htons(ARPHRD_ETHER);           // Define ethernet hardware type
    sll.sll_pkttype = (PACKET_BROADCAST);           // Broadcast packet
    sll.sll_protocol = htons(ETH_P_ARP);            // ARP protocol

    // Use sendto() to send packet to network
    if(sendto(sockfd, packet_out, 64, 0, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        err("Failed to send packet");
        goto out;
    }

    // Recieve incoming ARP reply
    socklen_t len = sizeof(sll);
    if(recvfrom(sockfd, packet_in, 64, 0, (struct sockaddr *)&sll, &len) < 0) {
        err("Failed to recieve packet");
        goto out;
    }

    // Reuse header pointers to discect recieved packet
    eth = (struct ethhdr *)packet_in;
    arp = (struct arp_header *)(packet_in + sizeof(struct ethhdr));

    // Display recieved MAC address
    debug("ARP Communication successful!");
    debug("Target MAC: %02X:%02X:%02X:%02X:%02X:%02X",
          arp->sender_mac[0] & 0xff,
          arp->sender_mac[1] & 0xff,
          arp->sender_mac[2] & 0xff,
          arp->sender_mac[3] & 0xff,
          arp->sender_mac[4] & 0xff,
          arp->sender_mac[5] & 0xff);

    // Clean up
out:
    if(sockfd > -1)
        close(sockfd);

    return EXIT_SUCCESS;
}