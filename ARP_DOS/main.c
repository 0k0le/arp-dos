/*/////////////////////////
 * ARP Discovery Project
 * Matthew Todd Geiger
 * 03:56:50 2019-03-01
 * main.c
/*/
/////////////////////

// Custom lib to handle ARP
#include "lib/arp.h"

int main(const int argc, const char *argv[])
{
    if (argc != 4)
    {
        printf("Usage: %s <INTERFACE> <TARGET_IP> <ROUTER_IP>\n", argv[0]);
        return 1;
    }
    
    const char *ifname = argv[1];
    const char *ip = argv[2];
    const char *ip2 = argv[3];
    return run(ifname, ip, ip2);
}