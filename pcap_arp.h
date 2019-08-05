#ifndef ARP_H
#define ARP_H

#include <arpa/inet.h>
#include <stdio.h>

struct packet_eth{
    uint8_t d_mac[6];
    uint8_t s_mac[6];
    uint16_t Etype;
};

struct packet_arp{
    uint16_t htype;
    uint16_t ptype;
    uint8_t hadd_len;
    uint8_t padd_len;
    uint16_t opcode;
    uint8_t s_mac[6];
    uint8_t s_ip[4];
    uint8_t t_mac[6];
    uint8_t t_ip[4];
};

void print_mac(uint8_t const* mac){
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(uint8_t const* ip){
    printf("%d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
}

#endif // ARP_H
