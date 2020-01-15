#include <iostream>
#include <pcap.h>
#include <cstdio>
#include <byteswap.h>

#include "main.h"

port_stats bandwidth[20];

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
#define SIZE_ETHERNET 14
    const struct sniff_ethernet *ethernet;
    const struct sniff_ip *ip;
    const struct sniff_tcp *tcp;
    const char *payload;
    u_int size_ip;
    u_int size_tcp;

//    std::cout << "Packet length: " << header->len << std::endl;

    ethernet = (struct sniff_ethernet*)(packet);
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;

    if (size_ip < 20) {
//        std::cout << "Invalid IP header length: " << size_ip << " bytes" << std::endl;
        return;
    }

    if (ip->ip_p != 6) {
//        printf("Not a TCP packet: %d\n", ip->ip_p);
        return;
    }

    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;
    if (size_tcp < 20) {
//        std::cout << "Invalid TCP header length: " << size_tcp << " bytes" << std::endl;
        return;
    }

    u_short src_port = __bswap_16(tcp->th_sport);
    u_short dst_port = __bswap_16(tcp->th_dport);

    payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

//    if (tcp->th_sport == 443 || tcp->th_dport == 443 || tcp->th_sport == 80 || tcp->th_dport == 80){
        printf("Src Port: %d, Dst Port: %d\n", src_port, dst_port);
//    }

    return;
}

int main(int argc, char* argv[]) {
    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct pcap_pkthdr header;
    const u_char *packet;
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        std::cout << "Failed to open device" << std::endl;
        return 1;
    }

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);

    return 0;
}
