#include <iostream>
#include <pcap.h>
#include <cstdio>
#include <byteswap.h>
#include <unordered_map>
#include <thread>
#include <mutex>
#include <chrono>
#include <signal.h>

#include "main.h"

using namespace std;

unordered_map<int, uint64_t> port_stats;
bool running = true;
pcap_t *handle;
mutex port_stats_mutex;

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
#define SIZE_ETHERNET 14
    const struct sniff_ethernet *ethernet;
    const struct sniff_ip *ip;
    const struct sniff_tcp *tcp;
    const char *payload;
    u_int size_ip;
    u_int size_tcp;

    ethernet = (struct sniff_ethernet*)(packet);
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;

    if (size_ip < 20) {
//        cout << "Invalid IP header length: " << size_ip << " bytes" << endl;
        return;
    }

    if (ip->ip_p != 6) {
//        printf("Not a TCP packet: %d\n", ip->ip_p);
        return;
    }

    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;
    if (size_tcp < 20) {
//        cout << "Invalid TCP header length: " << size_tcp << " bytes" << endl;
        return;
    }

    u_short src_port = __bswap_16(tcp->th_sport);
    u_short dst_port = __bswap_16(tcp->th_dport);

    payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

    port_stats_mutex.lock();
    port_stats[dst_port] += header->len;
    port_stats_mutex.unlock();

    return;
}

void signal_handler(int signal) {
    running = false;
    pcap_breakloop(handle);
}

int main(int argc, char* argv[]) {
    struct sigaction sig_int_handler;
    sig_int_handler.sa_handler = signal_handler;
    sigemptyset(&sig_int_handler.sa_mask);
    sig_int_handler.sa_flags = 0;

    sigaction(SIGINT, &sig_int_handler, nullptr);

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const u_char *packet;
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        std::cout << "Failed to open device" << std::endl;
        return 1;
    }

    auto pcap_thread_lambda = []() {
        pcap_loop(handle, -1, got_packet, NULL);
    };
    thread pcap_loop_thread(pcap_thread_lambda);

    int timer = 0;
    while (running) {
        this_thread::sleep_for(chrono::seconds(1));

        if (timer == 10) {
            timer = 0;
            if (port_stats_mutex.try_lock()) {
                for (pair<int, uint64_t> port : port_stats) {
                    cout << port.first << " : " << port.second << endl;
                }
                port_stats_mutex.unlock();
            }
        }

        timer++;
    }

    cout << "Shutting Down" << endl;

    pcap_loop_thread.join();

    pcap_close(handle);

    return 0;
}
