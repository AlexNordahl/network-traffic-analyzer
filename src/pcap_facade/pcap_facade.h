#ifndef PCAP_FACADE_H
#define PCAP_FACADE_H

#include "../net_headers/all_net_headers.h"
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
    void setFilter(std::string text, const bool optimize = false);

    std::pair<EtherFrame, const u_char* > next();

private:
    void extractIPv4Data();

    pcap_if_t* allDevs;
    pcap_if_t* selectedDev;
    pcap_t* handle;
    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    struct bpf_program fp;

    std::string selectedDevName;
    std::string ipv4;
    std::string mask;

    char errbuf[PCAP_ERRBUF_SIZE];
};

#endif
