#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include "pcap_arp.h"
#include <vector>

#define SIZE_ETHERNET 14
#define LEN_MAC 6
#define LEN_IP 4
#define PLEN 4
#define HTYPE 0x0001
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IP 0x0800

int compare_array(uint8_t a[], uint8_t b[]){
    int num = sizeof(a)/sizeof(uint8_t);
    int i;
    for(i =0; i<num; i++){
        if (a[i] != b[i]) return 1;
    }
    return 0;
}

void get_ip(char* dev, uint8_t ip[]){
    struct ifreq ifr;
    int s = socket(AF_INET, SOCK_DGRAM, 0);;

    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
        printf("Error");
    } else {
        int i;
        for (i = 0; i < 4; i++)
            ip[i] = (uint8_t)(ifr.ifr_addr.sa_data[i+2]);
    }
}

void get_mac(char* dev, uint8_t mac[]){
    struct ifreq ifr;
    int s = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(ifr.ifr_name, dev);
    if (0 == ioctl(s, SIOCGIFHWADDR, &ifr)) {
        int i;
        for (i = 0; i < 6; i++)
            mac[i] = (uint8_t)(ifr.ifr_addr.sa_data[i]);
    }
}

void send_arp(uint8_t op, char* dev, uint8_t s_mac[], uint8_t t_mac[], uint8_t s_ip[], uint8_t d_ip[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* p;

    if((p = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf)) == NULL)
    {
        printf("Error");
        return;
    }

    u_char buffer[1024];

    struct packet_eth eth;
    struct packet_arp arp;

    memset(buffer, 0, sizeof(buffer));
    int len = 0;

    // request
    if (op == 1){
        // eth->broadcasting, arp-> unknown
        memset(eth.d_mac, 0xff, sizeof(eth.d_mac));
        memcpy(eth.s_mac, s_mac, sizeof(eth.s_mac));
        eth.Etype = htons(ETHERTYPE_ARP);

        printf("arp request send\n");
        memset(arp.t_mac, 0x00, sizeof(arp.t_mac));
        memcpy(arp.s_mac, s_mac, sizeof(arp.s_mac));
        memcpy(arp.t_ip, d_ip, sizeof(arp.t_ip));
        memcpy(arp.s_ip, s_ip, sizeof(arp.s_ip));

        arp.htype = htons(HTYPE);
        arp.ptype = htons(ETHERTYPE_IP);
        arp.hadd_len = LEN_MAC;
        arp.padd_len = PLEN;
        arp.opcode = htons(op);

        memcpy(buffer, &eth, sizeof(eth));
        len += sizeof(eth);
        memcpy(buffer+len, &arp, sizeof(arp));
        len += sizeof(arp);
    }

    //reply
    if (op == 2){
        printf("\narp reply==============\n");
        memcpy(eth.d_mac, t_mac, sizeof(eth.d_mac));
        memcpy(eth.s_mac, s_mac, sizeof(eth.s_mac));
        eth.Etype = htons(ETHERTYPE_ARP);

        printf("d_mac: ");
        print_mac(eth.d_mac);
        printf("s_mac: ");
        print_mac(eth.s_mac);
        printf("=========================\n");

        memcpy(arp.t_mac, t_mac, sizeof(arp.t_mac));
        memcpy(arp.s_mac, s_mac, sizeof(arp.s_mac));
        memcpy(arp.t_ip, d_ip, sizeof(arp.t_ip));
        memcpy(arp.s_ip, s_ip, sizeof(arp.s_ip));

        arp.htype = htons(HTYPE);
        arp.ptype = htons(ETHERTYPE_IP);
        arp.hadd_len = LEN_MAC;
        arp.padd_len = PLEN;
        arp.opcode = htons(op);

        printf("t_mac: ");
        print_mac(arp.t_mac);
        printf("s_mac: ");
        print_mac(arp.s_mac);
        printf("t_ip: ");
        print_ip(arp.t_ip);
        printf("s_ip: ");
        print_ip(arp.s_ip);

        memcpy(buffer, &eth, sizeof(eth));
        len += sizeof(eth);
        memcpy(buffer+len, &arp, sizeof(arp));
        len += sizeof(arp);
    }

    if(pcap_sendpacket(p, buffer, len) == -1) printf("error\n");
    else printf("packet sent!\n");
    pcap_close(p);
}

void get_target_mac(char* dev, uint8_t s_mac[], uint8_t s_ip[], uint8_t my_ip[], uint8_t my_mac[],uint8_t target_mac[]){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    struct packet_eth* eth;
    struct packet_arp* arp;
    printf("receive packet...\n");
    //receive packet
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int i;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        send_arp(1, dev, my_mac, NULL, my_ip, s_ip);
        eth = (struct packet_eth *)(packet);
        if (eth->Etype != htons(ETHERTYPE_ARP)) continue;
        arp = (struct packet_arp *)(packet + SIZE_ETHERNET);
        if (ntohs(arp->opcode) != 2) continue;
        if (compare_array(arp->t_mac, my_mac) == 0) continue;
        if (compare_array(arp->s_ip, s_ip) == 0) continue;

        for (i = 0; i<6; i++){
            s_mac[i] = arp->s_mac[i];
        }
        break;
    }
}

//send_arp <interface> <sender ip> <target ip>
int main(int argc, char* argv[]) {
    uint8_t my_mac[6];
    uint8_t my_ip[4];

    char* dev = argv[1];
    uint8_t sender_ip[4];
    uint8_t target_ip[4];
    uint8_t sender_mac[6];
    uint8_t target_mac[6];
    int i;

    sender_ip[0] = (uint8_t)atoi(strtok(argv[2], "."));
    for (i = 1; i<4; i++){
        sender_ip[i] = (uint8_t)atoi(strtok(NULL, "."));
    }

    target_ip[0] = (uint8_t)atoi(strtok(argv[3], "."));
    for (i = 1; i<4; i++){
        target_ip[i] = (uint8_t)atoi(strtok(NULL, "."));
    }

    get_mac(dev, my_mac);
    get_ip(dev, my_ip);

    get_target_mac(dev, sender_mac, sender_ip, my_ip, my_mac, target_mac);

    printf("\nsource mac is ");
    print_mac(sender_mac);

    send_arp(2, dev, my_mac, sender_mac, target_ip, sender_ip);
    return 0;
}


