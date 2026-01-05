#ifndef PCAP_FACADE_H
#define PCAP_FACADE_H

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <pcap.h>
#include <sys/socket.h>

#include <array>
#include <cstring>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "../net_headers/all_net_headers.h"

class PcapFacade
{
public:
    PcapFacade();
    ~PcapFacade();

    PcapFacade(const PcapFacade&) = delete;
    PcapFacade& operator=(const PcapFacade&) = delete;

    PcapFacade(PcapFacade&&) = delete;
    PcapFacade& operator=(PcapFacade&&) = delete;

    void selectDevice(const std::string_view devName);
    void autoSelectDevice();

    void configure(int snaplen, bool promisc, int timeoutMs);
    void activate();

    std::string getSelectedDevice() const;
    std::string getIPv4() const;
    std::string getMask() const;
    std::vector<std::string> listAllDevices() const;
    void setFilter(std::string text, const bool optimize = false);

    std::pair<EtherFrame, const u_char*> next();

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
