#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <cstdio>
#include <iostream>
#include <cstring>
#include <pcap.h>
#include <netinet/tcp.h>

#define TCPHEADERSIZE 6*4

using namespace std;

void dump_pkt(const u_char* pkt_data, struct pcap_pkthdr* header);

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];//패킷을 캡쳐할 네트워크 어댑터 eth0
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        //handle:위에 open_live를 통해 받아온 파일 디스크립터
        //header : 이번에 읽은 패킷의 헤더에 대한 정보
        //packet : 이번에 읽은 패킷의 바이너리 값
        if (res == 0)continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        dump_pkt(packet, header);//패킷의 헤더에 대한 정보와 바이너리 값을 넘겨줌
    }

    pcap_close(handle);

}

void dump_pkt(const u_char* pkt_data, struct pcap_pkthdr* header) {
    struct ether_header* eth_hdr = (struct ether_header*)pkt_data;
    u_int16_t eth_type = ntohs(eth_hdr->ether_type);

    //if type is not IP, return function
    if (eth_type != ETHERTYPE_IP) return; // 

    struct ip* ip_hdr = (struct ip*)(pkt_data + sizeof(ether_header));

    u_int8_t ip_type = ip_hdr->ip_p;
    u_int8_t ip_offset = ip_hdr->ip_hl; //header length

    //if type if not TCP, return function
    if (ip_type != IPPROTO_TCP) return;

    struct tcphdr* tcp_hdr = (struct tcphdr*)(pkt_data + sizeof(ether_header) + sizeof(ip));
    printf("\nPacket Info====================================\n");

    //print pkt length
    printf("%u bytes captured\n", header->caplen);

    //print mac addr
    u_int8_t* dst_mac = eth_hdr->ether_dhost;
    u_int8_t* src_mac = eth_hdr->ether_shost;

    printf("Dst MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
        dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);

    printf("Src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
        src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);

    //print ip addr
    char src_ip[16], dst_ip[16];
    char* tmp = inet_ntoa(ip_hdr->ip_src);
    strcpy(src_ip, tmp);
    tmp = inet_ntoa(ip_hdr->ip_dst);
    strcpy(dst_ip, tmp);

    printf("Src IP : %s\n", src_ip);
    printf("Dst IP : %s\n", dst_ip);

    printf("Src Port : %d\n", ntohs(tcp_hdr->source));
    printf("Dst Port : %d\n", ntohs(tcp_hdr->dest));


    //print payload
    u_int32_t payload_len = header->caplen - sizeof(ether_header) - ip_offset * 4 - TCPHEADERSIZE;
    u_int32_t max = payload_len >= 16 ? 16 : payload_len;
    const u_char* pkt_payload = pkt_data + sizeof(ether_header) + ip_offset * 4 + TCPHEADERSIZE;
    printf("Payload : ");

    if (!payload_len) {
        printf("No payload\n");
    }
    else {
        for (int i = 0; i < max; i++) printf("%02x ", *(pkt_payload + i));
        printf("\n");
    }
}