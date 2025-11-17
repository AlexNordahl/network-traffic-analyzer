#ifndef PCAP_FACADE_H
#define PCAP_FACADE_H

#include <vector>
#include <string>
#include <stdexcept>
#include <pcap.h>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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

    void setFilter(const std::string_view expr);
    std::string next_packet();

private:
    void extractIPv4Data();

    pcap_if_t* allDevs;
    pcap_if_t* selectedDev;
    pcap_t* handle;

    std::string selectedDevName;
    std::string ipv4; 
    std::string mask;

    char errbuf[PCAP_ERRBUF_SIZE];
};

#endif
