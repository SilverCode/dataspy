#include <iostream>
#include <pcap.h>
#include <cstdio>
#include <byteswap.h>
#include <unordered_map>
#include <thread>
#include <mutex>
#include <chrono>
#include <signal.h>
#include <iomanip>

#include "main.h"

using namespace std;

unordered_map<int, uint64_t> port_stats;
uint64_t proto_stats[] = {0, 0, 0};
bool running = true;
pcap_t *handle;
mutex port_stats_mutex;
mutex proto_stats_mutex;

void update_proto_stats(proto protocol, uint64_t size) {
    proto_stats_mutex.lock();
    proto_stats[protocol] += size;
    proto_stats_mutex.unlock();
}

void handle_tcp_packet(const sniff_ip *ip, const struct pcap_pkthdr *header, const u_char *packet) {
    update_proto_stats(proto::tcp, header->len);

    const struct sniff_tcp *tcp;
    u_int size_tcp;
    u_int size_ip = IP_HL(ip) * 4;

    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;
    if (size_tcp < 20) {
        cerr << "Invalid TCP header length: " << size_tcp << " bytes" << endl;
        return;
    }

    u_short src_port = __bswap_16(tcp->th_sport);
    u_short dst_port = __bswap_16(tcp->th_dport);

//    const char *payload;
//    payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

    // TODO: Find better way to tell is we should be using the src_port or the dst_port
    u_short metric_port = dst_port > 9999 ? src_port : dst_port;

    port_stats_mutex.lock();
    port_stats[metric_port] += header->len;
    port_stats_mutex.unlock();
}

void handle_udp_packet(const sniff_ip *ip, const struct pcap_pkthdr *header, const u_char *packet) {
    update_proto_stats(proto::udp, header->len);

    u_int size_ip = IP_HL(ip) * 4;

    const struct sniff_udp *udp;
    udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);

    u_short src_port = __bswap_16(udp->uh_sport);
    u_short dst_port = __bswap_16(udp->uh_dport);

    // TODO: Find better way to tell is we should be using the src_port or the dst_port
    u_short metric_port = dst_port > 9999 ? src_port : dst_port;

    port_stats_mutex.lock();
    port_stats[metric_port] += header->len;
    port_stats_mutex.unlock();
}

void handle_icmp_packet(const sniff_ip *ip, const struct pcap_pkthdr *header, const u_char *packet) {
    update_proto_stats(proto::icmp, header->len);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    const struct sniff_ip *ip;

    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    u_int size_ip = IP_HL(ip) * 4;

    if (size_ip < 20) {
        return;
    }

    if (ip->ip_p == 6) {
        handle_tcp_packet(ip, header, packet);
    } else if (ip->ip_p == 17) {
        handle_udp_packet(ip, header, packet);
    } else if (ip->ip_p == 1) {
        handle_icmp_packet(ip, header, packet);
    }

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
    uint seconds = atoi(argv[2]);

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

        if (timer == seconds) {
            timer = 0;

            time_t current_time = chrono::system_clock::to_time_t(chrono::system_clock::now());
            tm tm = *localtime(&current_time);
            cout << put_time(&tm, "%F %T") << endl;

            if (proto_stats_mutex.try_lock()) {
                cout << "TCP " << proto_stats[proto::tcp] << " ";
                cout << "UDP " << proto_stats[proto::udp] << " ";
                cout << "ICMP " << proto_stats[proto::icmp] << endl;
                proto_stats_mutex.unlock();
            }

            if (port_stats_mutex.try_lock()) {
                for (pair<int, uint64_t> port : port_stats) {
                    cout << port.first << " " << port.second << endl;
                }
                port_stats_mutex.unlock();
            }

            cout << endl;
        }

        timer++;
    }

    cout << "Shutting Down" << endl;

    pcap_loop_thread.join();

    pcap_close(handle);

    return 0;
}
