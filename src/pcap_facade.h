#ifndef PCAP_FACADE_H
#define PCAP_FACADE_H

#include "net_headers/ether_frame.h"
#include "net_headers/ip_header.h"
#include "net_headers/arp_header.h"
#include "net_headers/tcp_header.h"
#include "net_headers/udp_header.h"
#include "net_headers/icmp_header.h"
#include "net_headers/dns_header.h"
#include <vector>
#include <array>
#include <string>
#include <stdexcept>
#include <pcap.h>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>

class PcapFacade
{
public:
    struct ParsedUDP
    {
        UdpHeader header;
        const u_char *data;
        const int dataLen;
    };

    PcapFacade();
    ~PcapFacade();

    void selectDevice(const std::string_view devName);
    void autoSelectDevice();

    void configure(int snaplen, bool promisc, int timeoutMs);
    void activate();

    std::string getSelectedDevice() const;
    std::string getIPv4() const;
    std::string getMask() const;
    std::vector<std::string> listAllDevices() const;
    int maskToCIDR(const std::string &mask) const;

    std::pair<EtherFrame, const u_char *> next();
    std::pair<IpHeader, const u_char *> parseIPV4(const u_char *payload);
    std::pair<TcpHeader, const u_char *> parseTCP(const u_char *data);
    ParsedUDP parseUDP(const u_char* data);
    IcmpHeader parseICMP(const u_char* data);
    ArpHeader parseARP(const u_char* payload);
    DnsHeader parseDNS(const u_char* data);

private:
    void extractIPv4Data();

    pcap_if_t *allDevs;
    pcap_if_t *selectedDev;
    pcap_t *handle;

    std::string selectedDevName;
    std::string ipv4;
    std::string mask;

    char errbuf[PCAP_ERRBUF_SIZE];
};

#endif
